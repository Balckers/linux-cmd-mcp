# 监听地址与后台运行

## 修改监听 IP

`--host` 修改的是 **MCP 服务绑定地址**，不是修改系统网卡。默认只监听
`127.0.0.1`，适合本机 IDE / 客户端；要让同一网段的其他机器连接，改绑本机
网卡地址或 `0.0.0.0`。

```bash
# 只允许本机访问（默认）
linux-cmd-mcp --transport sse --host 127.0.0.1 --port 8765

# 监听所有 IPv4 网卡；必须同时配置令牌
export LCMD_AUTH_TOKEN="$(openssl rand -hex 32)"
linux-cmd-mcp --transport sse --host 0.0.0.0 --port 8765

# 只监听指定网卡地址
linux-cmd-mcp --transport sse --host 192.168.1.20 --port 8765

# IPv6 回环
linux-cmd-mcp --transport sse --host ::1 --port 8765
```

优先级：`--host` / `--port` > `LCMD_HTTP_HOST` / `LCMD_HTTP_PORT` > 默认值。

启动前可先确认实际生效地址，不启动服务：

```bash
linux-cmd-mcp --check-config --host 0.0.0.0 --port 8765
```

`http.host` / `http.port` 是本次实际绑定值。运行中访问 `/healthz` 也会返回
`bind_host` / `bind_port`：

```bash
curl -s http://127.0.0.1:8765/healthz
```

修改监听 IP 后必须重启进程；当前进程不支持热切换监听地址。绑定非回环地址
但没有 `LCMD_AUTH_TOKEN` 时，前台和后台启动都会直接拒绝，不会裸奔。

## 公网隧道与 Host 白名单

MCP 传输层会校验 HTTP `Host` 头。经樱花隧道、frp、ngrok、Nginx 等暴露到公网时，
公网域名不是 `127.0.0.1` / `localhost` / `[::1]`，默认会返回 `421 Invalid Host header`。
这不是 Token 错误，Bearer 鉴权此时已经通过。

把公网 Host 加入白名单：

```bash
export LCMD_AUTH_TOKEN="$(openssl rand -hex 32)"
export LCMD_ALLOWED_HOSTS="nas-api-backup.example.com:*"
linux-cmd-mcp --transport streamable-http --host 127.0.0.1 --port 8765
```

`LCMD_ALLOWED_HOSTS` 的写法：

- `nas.example.com`：只允许不带端口的 Host
- `nas.example.com:*`：允许该域名的任意端口（隧道端口会变化时用这个）
- `nas.example.com:8765`：只允许指定端口
- `*`：关闭 SDK 的 Host 白名单（Bearer 与 Origin 校验仍然生效）

多个值用逗号分隔。先验证实际放行结果：

```bash
curl -i -H "Host: nas-api-backup.example.com:52877" \
  -H "Authorization: Bearer 你的令牌" \
  http://127.0.0.1:8765/sse
```

返回 `200` 并出现 `event: endpoint` 即表示 Host 校验通过；公网客户端再按
`https://公网域名/sse` 或 `https://公网域名/mcp` 接入。

## 后台运行

`--daemon` 会启动一个脱离终端的子进程，等待 `/healthz` 就绪后返回 PID、
监听地址和日志路径，适合没有 systemd 的临时环境。

```bash
linux-cmd-mcp --daemon --transport sse --host 127.0.0.1 --port 8765
```

默认状态文件与日志：

- PID：`$XDG_STATE_HOME/linux-cmd-mcp/server.pid`，未设置时
  `~/.local/state/linux-cmd-mcp/server.pid`
- 日志：同目录 `server.log`

可显式指定：

```bash
linux-cmd-mcp --daemon \
  --host 0.0.0.0 --port 8765 \
  --pid-file /run/linux-cmd-mcp/server.pid \
  --log-file /var/log/linux-cmd-mcp/server.log \
  --startup-timeout 15
```

`--daemon` 只在 `sse` / `streamable-http` 下可用；`stdio` 必须由宿主进程直接
拉起，不能后台化。

查看与停止：

```bash
linux-cmd-mcp --status --pid-file /run/linux-cmd-mcp/server.pid
linux-cmd-mcp --stop   --pid-file /run/linux-cmd-mcp/server.pid
```

- `--status`：运行中退出码 0，未运行退出码 1；输出 JSON，包含 `pid`、
  `host`、`port`、`health`、`healthy`。
- `--stop`：先 SIGTERM，超过 `--stop-timeout`（默认 10s）再 SIGKILL；PID
  文件不存在时视为已停止，返回 0。
- PID 文件内容是 JSON，权限 0600；停止前会校验 `/proc/<pid>/cmdline`，
  PID 被其他程序复用时拒绝发送信号。

日志是追加写入，不自动切割。长期运行建议配 `logrotate` 或交给 systemd
的 journal 管理。

## systemd（推荐的生产后台方式）

仓库提供了示例单元 [`examples/systemd/linux-cmd-mcp.service`](../examples/systemd/linux-cmd-mcp.service)。它以前台模式运行，由 systemd 负责拉起、重启和日志收集，不要再叠加 `--daemon`。

```bash
sudo useradd --system --create-home --home-dir /var/lib/linux-cmd-mcp \
  --shell /usr/sbin/nologin linuxcmd || true
sudo install -m 0644 examples/systemd/linux-cmd-mcp.service /etc/systemd/system/
sudo install -m 0600 /dev/null /etc/linux-cmd-mcp.env
sudo tee /etc/linux-cmd-mcp.env >/dev/null <<'EOF'
LCMD_AUTH_TOKEN=替换为至少16字符的随机令牌
LCMD_POLICY_MODE=standard
EOF
sudo chmod 0600 /etc/linux-cmd-mcp.env
sudo systemctl daemon-reload
sudo systemctl enable --now linux-cmd-mcp
sudo systemctl status linux-cmd-mcp
```

改 IP 时编辑单元里的 `--host`，然后：

```bash
sudo systemctl daemon-reload
sudo systemctl restart linux-cmd-mcp
```
