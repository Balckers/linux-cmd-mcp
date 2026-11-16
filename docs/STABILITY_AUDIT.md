# 稳定性审计报告

本报告只记录**已实际执行**的结果，所有数字均来自本项目目录下的脚本与命令，可原样复现。

- 审计时间：2026-11-16
- 环境：Ubuntu 22.04.5 / kernel 6.6.95 / Python 3.12.11 / mcp 1.30.0 / uvicorn 0.40.0
- 传输：SSE（`/sse` + `/messages/`），随机端口 + 随机 Bearer（`secrets.token_hex(16)`）
- 策略：`unrestricted`，`LCMD_ALLOWED_WORKDIRS=/tmp,/home/user`

## 1. 结论

| 维度 | 结果 | 证据 |
|---|---|---|
| 协议正确性 | 12 项握手 + 20 项 HTTP 传输全通过 | `check_handshake.py` / `check_http_transport.py` |
| 工具行为 | 6 工具 × 2 轮 = 245 项、3 轮 = 365 项全 PASS | `check_e2e_tools.py` |
| 单元/集成 | 145 passed | `pytest -q` |
| 全命令覆盖 | 1818 个命令 / 1890 条候选，坏候选 0 | `check_all_commands.py --json` |
| 并发 | 8 客户端 × 10 轮全部正确，内存 87MB → 91MB | `check_stability.py` |
| 非法入参 | 100 次全部 `INVALID_ARGUMENT`，之后仍可执行命令 | 同上 |
| 超时回收 | 3 次 `sleep 31` 超时，无残留进程 | 同上 |
| 长跑 | 60s / 567 次真实调用，RSS 前后持平（90988 KB） | 同上 |
| 优雅退出 | SIGTERM 后 stderr 无 traceback、无 ERROR | 同上 |

稳定性压测合计 **22 项 PASS / 0 FAIL**。

## 2. 压测项明细（`scripts/check_stability.py`）

1. **顺序重复**：3 轮 × 6 个工具（`get_system_info` / `check_command` / `describe_command` /
   `validate_working_directory` / `list_commands` / `execute_command`），每轮断言
   `isError=false` 且存在 `structuredContent`。
2. **并发**：8 个独立 SSE 会话并行，每会话 10 轮「`echo` 回显校验 + `list_commands` 分页」；
   全部断言行输出等于输入，服务器常驻内存增长 < 60MB。
3. **非法入参风暴**：单会话连续 100 次 `list_commands limit=0`，逐次断言
   `isError=true` 且文本含 `INVALID_ARGUMENT`；风暴后用同一服务器执行 `echo alive` 成功。
4. **超时回收**：3 次 `sleep 31` + `timeout_seconds=1`，断言 `timed_out=true`；
   随后 `pgrep -a -f "^sleep 31$"` 轮询 4s，断言无残留（SIGTERM 宽限期 1s 后仍未退出即失败）。
5. **长跑**：60s 内循环真实 `execute_command true`，每 50 次采样 `/proc/<pid>/status VmRSS`；
   实测 567 次调用、内存零增长。
6. **优雅退出**：SIGTERM → 15s 内退出，扫描日志无 `Traceback`、无 `ERROR` 行。

## 3. 一个已定位并修掉的“假故障”

早期压测在约 600 次连续调用后报 `httpx.ReadTimeout` → `McpError: Connection closed`，
看起来像服务端 SSE 断流。实际根因在**测试脚本自身**：

- 脚本用 `stderr=subprocess.PIPE` 启动服务器，却在整个压测期间不读取；
- INFO 日志约 100 字节/行，**Linux 管道缓冲区 64KB 写满后服务器阻塞在写日志上**；
- 事件循环停摆 → SSE 不再出帧 → 客户端读超时 → 会话关闭；
- 服务器进程本身一直存活（`srv.poll()` 为 `None`）。

对照组：把 stderr 改写到临时文件后，**3000 次连续 `execute_command` 全部成功**（本次实测），
DEBUG 级日志（36074 行）也无任何异常。脚本已固定为“日志落盘 + 末尾扫描”，
并在代码注释中写明原因，避免回归。

> 运维含义：服务器本身不阻塞；只有“stderr 接了无人读取的管道”才会卡。
> systemd / journald / 重定向到文件都属于正常用法。

## 4. 依赖自愈（环境重建后的最大遗漏点，已补）

云主机/容器重建会清空 apt 安装的包。实测环境重置后 `nickle` 消失，
`/usr/bin/xkeystone`（`x11-xserver-utils`）从 `runnable=true` 退化为
`missing_interpreter`，命令巡检由 `broken=0` 变成 `broken=1`。

新增 `scripts/bootstrap_deps.sh`：

- 幂等：`command -v nickle` 命中即跳过；
- 缺失则按 `apt-get` / `dnf` / `yum` 安装；
- 安装后调用项目自身的 `linux_cmd_mcp.exec_probe.probe_executability("/usr/bin/xkeystone")`
  做真实 execve 探测复核，失败则非零退出；
- `--check-only` 只检查不安装，适合放进部署前 gate。

实测输出：

```
[bootstrap] nickle 已存在：/usr/bin/nickle
[bootstrap] xkeystone 可执行：{"runnable": true, "reason": null}
[bootstrap] 依赖自愈完成（幂等，可重复执行）
```

随后全机巡检回到 `命令名=1818 候选路径=1890 坏候选分组 {}`。

## 5. 边界与已知限制（属设计选择，不是缺陷）

| 项 | 现状 |
|---|---|
| TLS | 服务器只监听 HTTP；TLS 由反向代理（nginx/caddy）终结，README/部署章节已写明 |
| 回环无令牌 | `127.0.0.1` 且未设 `LCMD_AUTH_TOKEN` 时允许无鉴权（本机信任模型）；非回环强制令牌，缺失即退出码 64 |
| 原语范围 | 只暴露 tools（6 个），未实现 resources/prompts——任务书 §一 只要求 tools |
| `xkeystone` 运行期 | `execve` 能通过；运行期缺发行版未随包的 `Nichrome` Nickle 库，按“能 exec 即通过”口径计入 |
| 指标 | 无 Prometheus/JSON 指标端点；可观测性依赖结构化日志 + `/healthz` |
| 会话保活 | SSE 心跳由官方 SDK（sse_starlette）负责，项目未额外注入自定义 ping 事件 |

## 6. 复现命令

```bash
cd linux-cmd-mcp
bash scripts/bootstrap_deps.sh                  # 依赖自愈（幂等）
python3 -m pytest -q                            # 145 passed
python3 scripts/check_handshake.py --verbose    # 12 项
python3 scripts/check_http_transport.py         # 20 项
python3 scripts/check_e2e_tools.py --rounds 2   # 245 项
python3 scripts/check_all_commands.py --json reports/command_health.json
python3 scripts/check_stability.py             # 22 项（默认 8 客户端 / 100 风暴 / 60s 长跑）
python3 scripts/check_stability.py --soak 180 --clients 12 --storm 300
```
