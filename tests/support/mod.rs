use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{
        Mutex, MutexGuard, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;

pub const IPV4: &str = "192.0.2.20";
pub const IPV6: &str = "2001:db8::20";

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
static TCP_HELPER: OnceLock<PathBuf> = OnceLock::new();
// Port discovery reads the shared /proc process list, including the Dropbear fixture.
static PROCESS_LIST: Mutex<()> = Mutex::new(());

fn checked(output: Output) -> Output {
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn terminate(process: &mut Child) {
    if matches!(process.try_wait(), Ok(None)) {
        let _ = process.kill();
        let _ = process.wait();
    }
}

fn namespace_command(pid: u32) -> Command {
    let mut command = Command::new("nsenter");
    command.args([
        "--target",
        &pid.to_string(),
        "--user",
        "--preserve-credentials",
        "--net",
    ]);
    command
}

fn wait_for_namespace(process: &mut Child, previous: &[PathBuf], log: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        assert!(
            process.try_wait().unwrap().is_none(),
            "{}",
            fs::read_to_string(log).unwrap()
        );
        if let Ok(current) = fs::read_link(format!("/proc/{}/ns/net", process.id()))
            && !previous.contains(&current)
        {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("network namespace was not created");
}

fn tcp_helper() -> &'static Path {
    TCP_HELPER.get_or_init(|| {
        let binary = Path::new(env!("CARGO_TARGET_TMPDIR")).join("ssh-allow-test-tcp");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/tcp.rs");
        checked(
            Command::new("rustc")
                .arg("--edition=2024")
                .arg(source)
                .arg("-o")
                .arg(&binary)
                .output()
                .unwrap(),
        );
        binary
    })
}

pub struct Firewall {
    directory: PathBuf,
    namespace: Option<Child>,
    service: Option<Child>,
    children: Vec<Child>,
    peer: Option<u32>,
    sshd_output: String,
    _process_list: MutexGuard<'static, ()>,
}

impl Firewall {
    pub fn new() -> Self {
        let process_list = PROCESS_LIST
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let directory = std::env::temp_dir().join(format!(
            "ssh-allow-test-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let mut firewall = Self {
            directory,
            namespace: None,
            service: None,
            children: Vec::new(),
            peer: None,
            sshd_output: "Port 22".into(),
            _process_list: process_list,
        };
        let log = firewall.log();
        firewall.namespace = Some(
            Command::new("unshare")
                .args(["--user", "--map-root-user", "--net", "sleep", "infinity"])
                .stderr(firewall.log_output())
                .spawn()
                .unwrap(),
        );
        wait_for_namespace(
            firewall.namespace.as_mut().unwrap(),
            &[fs::read_link("/proc/self/ns/net").unwrap()],
            &log,
        );
        firewall
    }

    fn command(&self) -> Command {
        namespace_command(self.namespace.as_ref().unwrap().id())
    }

    fn log(&self) -> PathBuf {
        self.directory.join("process.log")
    }

    pub fn log_contents(&self) -> String {
        fs::read_to_string(self.log()).unwrap()
    }

    fn log_output(&self) -> Stdio {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log())
            .unwrap()
            .into()
    }

    fn socket(&self) -> PathBuf {
        self.directory.join("ssh.sock")
    }

    pub fn run(&self, args: &[&str]) {
        checked(self.command().args(args).output().unwrap());
    }

    pub fn nft(&self, args: &[&str]) -> Value {
        let output = checked(
            self.command()
                .args(["nft", "-j"])
                .args(args)
                .output()
                .unwrap(),
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["nftables"].clone()
    }

    pub fn clients(&self, family: u8) -> BTreeMap<String, Value> {
        let name = format!("ssh_clients_v{family}");
        let objects = self.nft(&["list", "set", "inet", "ssh_access", &name]);
        let set = &objects
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item.get("set").is_some())
            .unwrap()["set"];
        match set["elem"].as_array() {
            Some(elements) => elements
                .iter()
                .map(|item| {
                    (
                        item["elem"]["val"].as_str().unwrap().to_owned(),
                        item["elem"].clone(),
                    )
                })
                .collect(),
            None => BTreeMap::new(),
        }
    }

    fn try_request(&self, ip: Option<&str>) -> io::Result<u16> {
        let mut stream = UnixStream::connect(self.socket())?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
        write!(
            stream,
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
        )?;
        if let Some(ip) = ip {
            write!(stream, "X-Real-IP: {ip}\r\n")?;
        }
        write!(stream, "\r\n")?;
        let mut status = String::new();
        BufReader::new(stream).read_line(&mut status)?;
        status
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, status))
    }

    pub fn request(&self, ip: &str) -> u16 {
        self.try_request(Some(ip)).expect("HTTP request failed")
    }

    pub fn health_request(&self, token: Option<&str>) -> (u16, Option<String>, bool) {
        let mut stream = UnixStream::connect(self.socket()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        write!(
            stream,
            "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
        )
        .unwrap();
        if let Some(token) = token {
            writeln!(stream, "X-Ssh-Allow-Health: {token}").unwrap();
        }
        write!(stream, "\r\n").unwrap();
        let mut response = String::new();
        BufReader::new(stream)
            .read_to_string(&mut response)
            .unwrap();
        let mut lines = response.lines();
        let status = lines
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let token = lines.take_while(|line| !line.is_empty()).find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("x-ssh-allow-health")
                .then(|| value.trim().to_owned())
        });
        let no_store = response
            .lines()
            .any(|line| line.eq_ignore_ascii_case("cache-control: no-store"));
        (status, token, no_store)
    }

    pub fn start_with_healthcheck(&mut self, ipv6: bool, timeout: u32, url: &str, interval: u32) {
        self.start_with_options(ipv6, timeout, Some((url, interval)));
    }

    pub fn health_proxy(&mut self, state: &str) -> (PathBuf, String) {
        let state_file = self.directory.join("health-proxy-state");
        fs::write(&state_file, state).unwrap();
        let mut process = self
            .command()
            .arg(tcp_helper())
            .arg("health-proxy")
            .arg(self.socket())
            .arg(&state_file)
            .stdout(Stdio::piped())
            .stderr(self.log_output())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(process.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        let port = ready
            .split_whitespace()
            .nth(1)
            .expect("health proxy did not report its port");
        self.children.push(process);
        (state_file, format!("http://127.0.0.1:{port}/health"))
    }

    pub fn policy_rules_loaded(&self) -> bool {
        self.nft(&["list", "table", "inet", "ssh_access"])
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["rule"]["chain"] == "ssh_policy")
    }

    pub fn policy_hook_installed(&self) -> bool {
        self.nft(&["list", "table", "inet", "ssh_access"])
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["rule"]["comment"] == "ssh-allow policy hook")
    }

    pub fn start(&mut self, ipv6: bool, timeout: u32) {
        self.start_with_options(ipv6, timeout, None);
    }

    fn start_with_options(&mut self, ipv6: bool, timeout: u32, healthcheck: Option<(&str, u32)>) {
        if let Some(mut service) = self.service.take() {
            terminate(&mut service);
        }
        if self.socket().exists() {
            fs::remove_file(self.socket()).unwrap();
        }
        let mut command = self.command();
        let bin = self.directory.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let sshd = bin.join("sshd");
        fs::write(&sshd, "#!/bin/sh\n[ \"$1\" = '-G' ] || exit 1\nprintf '%s\\n' \"$SSH_ALLOW_TEST_SSHD_OUTPUT\"\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&sshd, fs::Permissions::from_mode(0o755)).unwrap();
        command
            .env("SSH_ALLOW_TEST_SSHD_OUTPUT", &self.sshd_output)
            .env(
                "PATH",
                std::env::join_paths(
                    std::iter::once(bin)
                        .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
                )
                .unwrap(),
            )
            .arg(env!("CARGO_BIN_EXE_ssh-allow"))
            .arg("--socket")
            .arg(self.socket())
            .arg("--timeout")
            .arg(timeout.to_string());
        if ipv6 {
            command.arg("--ipv6");
        }
        if let Some((url, interval)) = healthcheck {
            command.arg("--healthcheck-url").arg(url);
            command
                .arg("--healthcheck-interval")
                .arg(interval.to_string());
        }
        self.service = Some(
            command
                .stdout(self.log_output())
                .stderr(self.log_output())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            assert!(
                self.service.as_mut().unwrap().try_wait().unwrap().is_none(),
                "{}",
                fs::read_to_string(self.log()).unwrap()
            );
            if matches!(self.try_request(None), Ok(400)) {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!(
            "service did not become ready: {}",
            fs::read_to_string(self.log()).unwrap()
        );
    }

    pub fn network(&mut self) {
        self.run(&["ip", "link", "set", "lo", "up"]);
        self.run(&[
            "ip", "link", "add", "server", "type", "veth", "peer", "name", "client",
        ]);
        self.children.push(
            self.command()
                .args(["unshare", "--net", "sleep", "infinity"])
                .stderr(self.log_output())
                .spawn()
                .unwrap(),
        );
        let previous = fs::read_link(format!(
            "/proc/{}/ns/net",
            self.namespace.as_ref().unwrap().id()
        ))
        .unwrap();
        let log = self.log();
        let peer = self.children.last_mut().unwrap();
        wait_for_namespace(
            peer,
            &[previous, fs::read_link("/proc/self/ns/net").unwrap()],
            &log,
        );
        let peer = peer.id();
        self.peer = Some(peer);
        self.run(&["ip", "link", "set", "client", "netns", &peer.to_string()]);
        for (pid, interface, ipv4, ipv6) in [
            (
                self.namespace.as_ref().unwrap().id(),
                "server",
                "192.0.2.10",
                "2001:db8::10",
            ),
            (peer, "client", IPV4, IPV6),
        ] {
            for args in [
                vec![
                    "ip",
                    "address",
                    "add",
                    &format!("{ipv4}/24"),
                    "dev",
                    interface,
                ],
                vec![
                    "ip",
                    "-6",
                    "address",
                    "add",
                    &format!("{ipv6}/64"),
                    "dev",
                    interface,
                    "nodad",
                ],
                vec!["ip", "link", "set", interface, "up"],
            ] {
                checked(namespace_command(pid).args(args).output().unwrap());
            }
        }
        self.children.push(
            self.command()
                .arg(tcp_helper())
                .arg("serve")
                .stdout(Stdio::piped())
                .stderr(self.log_output())
                .spawn()
                .unwrap(),
        );
        let stdout = self.children.last_mut().unwrap().stdout.take().unwrap();
        let mut ready = String::new();
        BufReader::new(stdout).read_line(&mut ready).unwrap();
        assert_eq!(
            ready.trim(),
            "ready",
            "{}",
            fs::read_to_string(self.log()).unwrap()
        );
    }

    pub fn assert_connection(&self, family: u8, allowed: bool) {
        self.assert_port(family, 22, allowed);
    }

    pub fn assert_port(&self, family: u8, port: u16, allowed: bool) {
        let address = if family == 4 {
            format!("192.0.2.10:{port}")
        } else {
            format!("[2001:db8::10]:{port}")
        };
        let output = namespace_command(self.peer.unwrap())
            .arg(tcp_helper())
            .args(["connect", &address])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(if allowed { 0 } else { 2 }),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    pub fn sshd_config(&mut self, output: &str) {
        self.sshd_output = output.into();
    }

    pub fn dropbear(&mut self, args: &[&str]) {
        self.children.push(
            self.command()
                .arg(tcp_helper())
                .arg("dropbear")
                .args(args)
                .stdout(Stdio::piped())
                .stderr(self.log_output())
                .spawn()
                .unwrap(),
        );
        let stdout = self.children.last_mut().unwrap().stdout.take().unwrap();
        let mut ready = String::new();
        BufReader::new(stdout).read_line(&mut ready).unwrap();
        assert_eq!(ready.trim(), "ready");
    }
}

impl Drop for Firewall {
    fn drop(&mut self) {
        if let Some(service) = self.service.as_mut() {
            terminate(service);
        }
        for process in self.children.iter_mut().rev() {
            terminate(process);
        }
        if let Some(namespace) = self.namespace.as_mut() {
            terminate(namespace);
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}
