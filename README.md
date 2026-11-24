# ssh-allow

[English](README_en.md)

`ssh-allow` 管理 SSH 临时白名单。调用放行接口后，指定 IP 默认可连接 SSH 300 秒；再次调用会刷新有效期。默认启用 IPv4，可选启用 IPv6。

> [!WARNING]
> 启动服务前先配置外部放行接口，并保留当前 SSH 会话，直到新连接测试成功。`--healthcheck-url` 只检查指定的健康路径，不能代替放行接口测试。

## 安装

需要 Linux 和支持 JSON 的 `nft`。从 [Releases](https://github.com/antonchen/ssh-allow/releases) 下载对应架构的安装包，解压后执行：

```sh
sudo install -m 0755 ssh-allow /usr/local/bin/ssh-allow
sudo install -m 0644 deploy/ssh-allow.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-allow
```

systemd 服务以 `daemon` 用户运行，通过 `CAP_NET_ADMIN` 管理规则。日志查看：

```sh
journalctl -u ssh-allow -f
```

## 参数

```sh
ssh-allow --timeout 600 --socket /run/ssh-allow/ssh-allow.sock --ipv6
```

| 参数 | 含义 | 默认值 |
| --- | --- | --- |
| `--timeout SECONDS` | 白名单有效期，正整数秒数 | `300` |
| `--socket PATH` | Unix socket 路径 | `/run/ssh-allow/ssh-allow.sock` |
| `--ipv6` | 开启 IPv6 白名单 | 关闭 |
| `--healthcheck-url URL` | 外部健康检查 URL；可在 URL 中配置 HTTP Basic 身份验证，例如 `https://user:password@example.com/ssh/health` | 不启用 |
| `--healthcheck-interval DURATION` | 健康检查间隔，支持秒和分钟后缀，如 `30s`、`5m`；纯数字按秒解释 | `5m` |
| `--help`、`-h` | 显示帮助 | — |

使用 systemd 时修改 `ExecStart`，然后重新加载单元并重启服务。自定义 socket 路径时同步调整单元的清理路径、运行目录和反向代理配置；手动运行需准备父目录并清理旧 socket。

## 接口

对外提供接口时，建议使用 HTTPS 和 HTTP Basic 身份验证。放行接口为 `GET /`，通过 `X-Real-IP` 接收单个 IP；健康检查接口为 `GET /health`。配置健康检查时，反向代理需将外部健康路径转发到后端 `/health`。

```sh
curl --fail --unix-socket /run/ssh-allow/ssh-allow.sock \
    -H 'X-Real-IP: 192.0.2.1' http://localhost/
```

| 状态码 | 含义 |
| --- | --- |
| `204` | 已放行，成功日志包含 IP 和有效期 |
| `400` | IP 缺失、格式错误或 IPv6 未开启 |
| `500` | nftables 更新失败，日志包含具体错误 |

接口响应体为空。[Nginx 示例](deploy/nginx.conf)使用 `location`，将 `/ssh` 和 `/ssh/health` 分别转发到后端的 `/` 和 `/health`。

## SSH 客户端

在 `~/.ssh/config` 中添加以下配置，连接前自动请求放行：

```sshconfig
Match originalhost example.com exec "curl -4 --noproxy '*' -fsS --connect-timeout 5 --max-time 10 https://example.com/ssh >/dev/null"
Match all
```

将 `example.com` 和接口 URL 替换为实际值。`originalhost` 匹配命令行中的主机名或别名；`Match all` 结束这段条件配置。随后照常使用 `ssh example.com`。

示例使用 IPv4，SSH 连接也应使用 IPv4，例如 `ssh -4 example.com`，使放行请求与 SSH 连接的来源 IP 一致。`exec` 请求失败时不会阻止 SSH 尝试连接。

## 使用约定

- 服务启动时初始化 `inet ssh_access` 和白名单集合，并保留已有白名单；运行中只更新集合。规则被外部删除后需重启服务。
- SSH 端口在启动时识别：运行中的 Dropbear 读取 `-p` 参数，否则从 OpenSSH 的 `sshd -G` 有效配置中提取 `Port`。支持多个端口，未提取到端口时使用 `22`；识别结果写入启动日志。Dropbear 应先启动，OpenSSH 的 `sshd` 需在服务的 `PATH` 中，配置需对运行用户可读。
- IPv4 集合为 `ssh_clients_v4`，IPv6 集合为 `ssh_clients_v6`。开启对应协议后，已建立及关联连接、回环和白名单可访问 SSH；其他访问已识别 SSH 端口的流量被拒绝。未开启 IPv6 时，这些端口的 IPv6 连接全部拒绝。
- 其他 nftables 表保持原样，其拒绝规则仍然有效。
- 配置 `--healthcheck-url` 后，服务先清空策略子链，再启动健康端点并检查外部反向代理。首次检查成功后才加载策略规则并挂接输入链；失败时每 10 秒重试。运行期间按 `--healthcheck-interval` 指定的间隔检查，默认 `5m`；失败后每 10 秒重试，连续失败两次时清空输入链，成功后立即恢复策略跳转。健康端点返回 `204` 和 `X-Ssh-Allow-Health` UUID 响应头，并设置 `Cache-Control: no-store`；代理也应为该路径禁用缓存。UUID 在内存中保存 10 秒，由服务本地校验。该端点不修改白名单。停用拦截期间，SSH 访问由主机上的其他防火墙规则决定。
- socket 权限为 `0666`，本机用户均可调用。容器应挂载整个 `/run/ssh-allow` 目录，使服务重启后新 socket 仍可访问。

## 测试

```sh
cargo test --release --locked --test firewall
```

14 个 Rust 集成测试在独立用户和网络命名空间中运行，需要 `rustc`、`nft`、`ip`、`unshare`、`nsenter` 及内核命名空间支持，覆盖 HTTP、健康检查故障与恢复、端口识别和防火墙行为。
