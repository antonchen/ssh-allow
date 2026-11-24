# ssh-allow

[简体中文](README.md)

A small service for temporary SSH allowlists. Calling the allowlist endpoint lets the specified IP connect to SSH for 300 seconds by default; repeated calls renew the timeout. IPv4 is enabled by default, with optional IPv6 support.

> [!WARNING]
> Configure the public allowlist endpoint before starting the service, and keep the current SSH session open until a new connection succeeds. `--healthcheck-url` checks only its configured health path; it does not verify the allowlist endpoint.

## Installation

Requires Linux and `nft` with JSON support. Download the archive for your architecture from [Releases](https://github.com/antonchen/ssh-allow/releases), extract it, and run:

```sh
sudo install -m 0755 ssh-allow /usr/local/bin/ssh-allow
sudo install -m 0644 deploy/ssh-allow.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-allow
```

The systemd service runs as `daemon` with `CAP_NET_ADMIN`. View logs with:

```sh
journalctl -u ssh-allow -f
```

## Options

```sh
ssh-allow --timeout 600 --socket /run/ssh-allow/ssh-allow.sock --ipv6
```

| Option | Description | Default |
| --- | --- | --- |
| `--timeout SECONDS` | Allowlist duration in positive integer seconds | `300` |
| `--socket PATH` | Unix socket path | `/run/ssh-allow/ssh-allow.sock` |
| `--ipv6` | Enable IPv6 allowlisting | Disabled |
| `--healthcheck-url URL` | Public health-check URL; HTTP Basic authentication can be supplied in the URL, for example `https://user:password@example.com/ssh/health` | Disabled |
| `--healthcheck-interval DURATION` | Health-check interval. Supports seconds and minutes, such as `30s` or `5m`. Bare numbers mean seconds. | `5m` |
| `--help`, `-h` | Show help | — |

For systemd, edit `ExecStart`, reload the unit, and restart the service. When changing the socket path, also update the cleanup path, runtime directory, and reverse-proxy configuration. For manual startup, create the parent directory and remove any old socket first.

## API

The allowlist endpoint is `GET /` and accepts one IP in `X-Real-IP`. The health endpoint is `GET /health`. Use HTTPS and HTTP Basic authentication for public access. When health checks are enabled, proxy the external health path to backend `/health`.

```sh
curl --fail --unix-socket /run/ssh-allow/ssh-allow.sock \
    -H 'X-Real-IP: 192.0.2.1' http://localhost/
```

| Status | Meaning |
| --- | --- |
| `204` | Access granted; the log includes the IP and duration |
| `400` | Missing or invalid IP, or IPv6 is disabled |
| `500` | nftables update failed; details are logged |

Responses have no body. The [Nginx example](deploy/nginx.conf) uses `location` to proxy `/ssh` and `/ssh/health` to backend `/` and `/health`, respectively.

## SSH client

Add this to `~/.ssh/config` to request access before connecting:

```sshconfig
Match originalhost example.com exec "curl -4 --noproxy '*' -fsS --connect-timeout 5 --max-time 10 https://example.com/ssh >/dev/null"
Match all
```

Replace `example.com` and the endpoint URL with your values. `originalhost` matches the hostname or alias entered on the command line. `Match all` ends this conditional configuration. Then connect as usual with `ssh example.com`.

The example uses IPv4; use IPv4 for SSH too, such as `ssh -4 example.com`, so both requests use the same source IP. A failed `exec` request does not prevent SSH from attempting to connect.

## Behavior

- At startup, the service initializes `inet ssh_access` and its allowlist sets while preserving existing entries. While running, requests only update the sets. Restart the service if its rules are deleted externally.
- SSH ports are detected at startup: from `-p` arguments of running Dropbear processes, or from `Port` entries in OpenSSH's effective `sshd -G` output. Multiple ports are supported; the fallback is `22`. Detected ports are logged. Start Dropbear first. For OpenSSH, `sshd` must be in the service's `PATH`, and its configuration must be readable by the service user.
- IPv4 uses `ssh_clients_v4`; IPv6 uses `ssh_clients_v6`. With a family enabled, established and related connections, loopback traffic, and allowlisted sources can access SSH. Other traffic to detected SSH ports is rejected. With IPv6 disabled, all IPv6 connections to those ports are rejected.
- Other nftables tables remain unchanged, and their rejection rules still apply.
- With `--healthcheck-url`, the service clears the policy chain before starting the health endpoint and checking the external reverse proxy. Policy rules and the input-chain jump are installed only after the first successful check; failures are retried every 10 seconds. During normal operation, the interval is set by `--healthcheck-interval` and defaults to `5m`. Two consecutive failures flush the input chain; a successful check immediately restores the policy jump. The health endpoint returns `204` with an `X-Ssh-Allow-Health` UUID response header and sets `Cache-Control: no-store`; configure the proxy not to cache this path as well. The service validates the UUID locally and keeps it in memory for 10 seconds. The endpoint does not modify the allowlist. While filtering is disabled, SSH access depends on the host's other firewall rules.
- The socket has mode `0666`, allowing local users to call the API. Containers should mount the entire `/run/ssh-allow` directory so a recreated socket remains accessible after a service restart.

## Tests

```sh
cargo test --release --locked --test firewall
```

The 14 Rust integration tests run in isolated user and network namespaces. They require `rustc`, `nft`, `ip`, `unshare`, `nsenter`, and kernel namespace support. They cover HTTP, health-check failures and recovery, port detection, and firewall behavior.
