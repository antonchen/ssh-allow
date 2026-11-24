use std::{
    error::Error, ffi::OsString, num::NonZeroU32, path::PathBuf, process::Command, time::Duration,
};

use nftables::{
    expr::{Expression, NamedExpression, Payload},
    schema::{NfCmd, NfListObject, NfObject, Nftables},
    stmt::Statement,
};

pub struct Config {
    pub socket: PathBuf,
    pub timeout: u32,
    pub ipv6: bool,
    pub healthcheck: Option<(reqwest::Client, reqwest::Url)>,
    pub healthcheck_interval: Duration,
}

pub fn parse_args(args: impl Iterator<Item = OsString>) -> Result<Option<Config>, Box<dyn Error>> {
    let mut config = Config {
        socket: PathBuf::from("/run/ssh-allow/ssh-allow.sock"),
        timeout: 300,
        ipv6: false,
        healthcheck: None,
        healthcheck_interval: Duration::from_secs(300),
    };
    let mut args = args;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--ipv6") => config.ipv6 = true,
            Some("--socket") => {
                config.socket = args.next().ok_or("--socket requires a path")?.into();
            }
            Some("--timeout") => {
                config.timeout = args
                    .next()
                    .ok_or("--timeout requires seconds")?
                    .to_str()
                    .ok_or("--timeout requires a positive integer")?
                    .parse::<NonZeroU32>()?
                    .get();
            }
            Some("--healthcheck-url") => {
                let url = args
                    .next()
                    .ok_or("--healthcheck-url requires a URL")?
                    .to_string_lossy()
                    .into_owned();
                let url = reqwest::Url::parse(&url)?;
                if url.scheme() != "https" && url.scheme() != "http" {
                    return Err("health-check URL must use HTTP or HTTPS".into());
                }
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(5))
                    .redirect(reqwest::redirect::Policy::none())
                    .build()?;
                config.healthcheck = Some((client, url));
            }
            Some("--healthcheck-interval") => {
                let value = args
                    .next()
                    .ok_or("--healthcheck-interval requires a duration")?;
                config.healthcheck_interval = parse_healthcheck_interval(
                    value
                        .to_str()
                        .ok_or("--healthcheck-interval requires a duration")?,
                )?;
            }
            Some("--help" | "-h") => {
                println!(
                    "Usage: ssh-allow [--timeout SECONDS] [--socket PATH] [--ipv6] [--healthcheck-url URL] [--healthcheck-interval DURATION]\n\n\
                     --timeout SECONDS  Allowlist duration, positive integer (default: 300)\n\
                     --socket PATH      Unix socket path (default: /run/ssh-allow/ssh-allow.sock)\n\
                     --ipv6             Enable IPv6 SSH allowlisting (default: disabled)\n\
                     --healthcheck-url URL  Public health endpoint URL (optional; supports URL Basic Auth)\n\
                     --healthcheck-interval DURATION  Health-check interval (default: 5m; units: s, m)"
                );
                return Ok(None);
            }
            _ => return Err(format!("unknown argument: {}", arg.to_string_lossy()).into()),
        }
    }
    Ok(Some(config))
}

fn parse_healthcheck_interval(value: &str) -> Result<Duration, Box<dyn Error>> {
    let (value, multiplier) = if let Some(value) = value.strip_suffix('s') {
        (value, 1)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60)
    } else {
        (value, 1)
    };
    let seconds = value
        .parse::<NonZeroU32>()?
        .get()
        .checked_mul(multiplier)
        .ok_or("health-check interval is too large")?;
    Ok(Duration::from_secs(u64::from(seconds)))
}

pub fn ssh_ports() -> Result<Vec<u16>, Box<dyn Error>> {
    let mut ports = Vec::new();
    let mut dropbear = false;
    for entry in std::fs::read_dir("/proc")?.flatten() {
        if std::fs::read_to_string(entry.path().join("comm"))
            .is_ok_and(|name| name.trim() == "dropbear")
        {
            let command = std::fs::read(entry.path().join("cmdline"))?;
            let command = String::from_utf8_lossy(&command);
            let mut args = command.split('\0').skip(1);
            let mut process_ports = Vec::new();
            while let Some(arg) = args.next() {
                let value = if arg == "-p" {
                    args.next()
                } else {
                    arg.strip_prefix("-p").filter(|value| !value.is_empty())
                };
                if let Some(port) = value
                    .and_then(|value| value.rsplit(':').next())
                    .and_then(|value| value.parse::<u16>().ok())
                    .filter(|port| *port != 0)
                {
                    process_ports.push(port);
                }
            }
            if process_ports.is_empty() {
                process_ports.push(22);
            }
            ports.extend(process_ports);
            dropbear = true;
        }
    }
    if !dropbear {
        match Command::new("sshd").arg("-G").output() {
            Ok(output) if output.status.success() => {
                let config = String::from_utf8(output.stdout)?;
                ports.extend(config.lines().filter_map(|line| {
                    let mut fields = line.split_whitespace();
                    fields
                        .next()
                        .filter(|key| key.eq_ignore_ascii_case("port"))?;
                    fields.next()?.parse::<u16>().ok().filter(|port| *port != 0)
                }));
            }
            Ok(output) => {
                return Err(format!(
                    "sshd -G failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                )
                .into());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if ports.is_empty() {
        ports.push(22);
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

pub fn rulesets(
    timeout: u32,
    ipv6: bool,
    ports: &[u16],
    defer_input_chain: bool,
) -> Result<(Nftables<'static>, Nftables<'static>, NfObject<'static>), Box<dyn Error>> {
    let port_match = if ports.len() == 1 {
        Expression::Number(u32::from(ports[0]))
    } else {
        serde_json::from_value(serde_json::json!({ "set": ports }))?
    };
    let mut ruleset: Nftables<'_> = serde_json::from_str(include_str!("ruleset.json"))?;
    let objects = ruleset.objects.to_mut();
    for object in objects.iter_mut() {
        if let NfObject::CmdObject(NfCmd::Add(NfListObject::Set(set))) = object {
            set.timeout = Some(timeout);
        }
        if let NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(rule))) = object {
            for statement in rule.expr.to_mut() {
                if let Statement::Match(value) = statement
                    && matches!(&value.left, Expression::Named(NamedExpression::Payload(Payload::PayloadField(field)))
                        if field.protocol == "tcp" && field.field == "dport")
                {
                    value.right = port_match.clone();
                }
            }
        }
    }
    if ipv6 {
        let index = objects
            .iter()
            .position(|object| {
                matches!(object, NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(rule)))
                if rule.comment.as_deref() == Some("IPv6 SSH reject"))
            })
            .ok_or("embedded ruleset is missing the IPv6 reject rule")?;
        let reject = objects.remove(index);
        objects.push(reject);
    } else {
        objects.retain(|object| {
            !matches!(object, NfObject::CmdObject(NfCmd::Add(NfListObject::Set(set)))
                if set.name == "ssh_clients_v6")
                && !matches!(object, NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(rule)))
                    if rule.comment.as_deref() == Some("IPv6 SSH allowlist"))
        });
    }
    let hook_rule = objects
        .iter()
        .find(|object| {
            matches!(object,
                NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(rule)))
                    if rule.comment.as_deref() == Some("ssh-allow policy hook")
            )
        })
        .cloned()
        .ok_or("embedded ruleset is missing the SSH policy hook")?;
    let (initial_objects, input_objects): (Vec<_>, Vec<_>) = objects.iter().cloned().partition(
        |object| {
            !defer_input_chain || (!matches!(object,
                NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(chain))) if chain.name == "input"
            ) && !matches!(object,
                NfObject::CmdObject(NfCmd::Flush(nftables::schema::FlushObject::Chain(chain))) if chain.name == "input"
            ) && !matches!(object,
                NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(rule)))
                    if rule.chain == "ssh_policy"
                        || rule.comment.as_deref() == Some("ssh-allow policy hook")
            ))
        },
    );
    Ok((
        Nftables {
            objects: initial_objects.into(),
        },
        Nftables {
            objects: input_objects.into(),
        },
        hook_rule,
    ))
}
