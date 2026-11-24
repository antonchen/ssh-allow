use std::{
    env,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::net::UnixStream,
    process, thread,
    time::Duration,
};

fn main() {
    let args: Vec<_> = env::args().collect();
    match args[1].as_str() {
        "dropbear" => {
            std::fs::write("/proc/self/comm", "dropbear").unwrap();
            println!("ready");
            std::io::stdout().flush().unwrap();
            loop {
                thread::park();
            }
        }
        "serve" => {
            for address in ["192.0.2.10", "[2001:db8::10]"] {
                for port in [22, 2200, 2222] {
                    let address = format!("{address}:{port}");
                    let listener = TcpListener::bind(address).unwrap();
                    thread::spawn(move || {
                        for stream in listener.incoming() {
                            let mut stream = stream.unwrap();
                            stream
                                .set_read_timeout(Some(Duration::from_secs(3)))
                                .unwrap();
                            let mut data = [0; 2];
                            stream.read_exact(&mut data).unwrap();
                            stream.write_all(&data).unwrap();
                        }
                    });
                }
            }
            println!("ready");
            std::io::stdout().flush().unwrap();
            loop {
                thread::park();
            }
        }
        "health-proxy" => {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            println!("ready {}", listener.local_addr().unwrap().port());
            std::io::stdout().flush().unwrap();
            for incoming in listener.incoming() {
                let mut client = incoming.unwrap();
                let mut request = Vec::new();
                let mut chunk = [0; 1024];
                loop {
                    let count = client.read(&mut chunk).unwrap();
                    request.extend_from_slice(&chunk[..count]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                if fs::read_to_string(&args[3]).unwrap() != "healthy" {
                    client
                        .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .unwrap();
                    continue;
                }
                let mut backend = UnixStream::connect(&args[2]).unwrap();
                backend.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
                let mut response = Vec::new();
                backend.read_to_end(&mut response).unwrap();
                client.write_all(&response).unwrap();
            }
        }
        "connect" => {
            let address: SocketAddr = args[2].parse().unwrap();
            let mut stream = match TcpStream::connect_timeout(&address, Duration::from_secs(3)) {
                Ok(stream) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    process::exit(2);
                }
                Err(error) => panic!("{error}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream.write_all(b"ok").unwrap();
            let mut data = [0; 2];
            stream.read_exact(&mut data).unwrap();
            assert_eq!(&data, b"ok");
        }
        mode => panic!("unknown mode: {mode}"),
    }
}
