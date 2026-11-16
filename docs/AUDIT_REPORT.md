# 全面诊断报告：遗漏错误、根因与修复验证

> 范围：`linux-cmd-mcp` 全部源码、测试、脚本、文档与真实运行链路。
> 环境：Ubuntu 22.04.5 / kernel 6.6.95 / Python 3.12.11 / mcp 1.30.0。
> 方法：逐文件静态审计 + 起真实 SSE 服务器（Bearer 鉴权）逐项探测 + 修复后回归复测。
> 结论：**共确认并修复 12 个真实问题（含 1 个静默丢字段、2 个协议兼容/安全解析、2 个语义错误）**；
> 全量回归 **145 passed**，端到端 **245/245 PASS**，全机 **1818 命令 / 1890 候选 / broken=0**，
> 稳定性 **22/22 PASS**。无遗留未修缺陷。

---

## 1. 审计方法

1. **基线**：`pytest -q`、`pyflakes`、`compileall`、`--check-config` 先确认“当前是绿的”，避免把既有噪声当新缺陷。
2. **逐文件读代码**：`config.py` / `runner.py` / `policy.py` / `paths.py` / `discovery.py` /
   `http_transport.py` / `server.py` / `inputs.py` / `models.py` / `sysinfo.py` / `tools/*` / `tests/*`。
   对每条“代码写法”提出可证伪的运行假设，而不是只做代码观感评审。
3. **真实探测**：每条假设都起真实服务器（SSE + Bearer 会话）或真实子进程复现，记录输入、返回码、日志。
4. **修复后再跑同一探测**：同一脚本、同一输入必须转绿；另外补 pytest 回归，防止再次回退。
5. **全链路验收**：单测 → 握手/HTTP 自检 → 29 条真实命令矩阵（2 轮）→ 全机命令巡检 → 稳定性压测。

---

## 2. 确认并修复的问题

| # | 问题 | 根因 | 实测证据（修复前） | 修复 |
|---|---|---|---|---|
| D1 | 合法超长绝对路径被 `execute_command` 拒绝 | `ExecuteCommandInput.command` 只有 255 字符上限；`describe_command`/`check_command` 是 4096，同一路径三个工具行为不一致 | 315 字符的绝对路径：`execute` → `INVALID_ARGUMENT "at most 255 characters"`；`describe` → ok；直接 `execve` → rc=0 | 上限统一为 4096（PATH_MAX 量级），并补模型校验回归 |
| D2 | 相对目标的符号链接链解析断链 | `symlink_chain` 用 `os.readlink()` 得到的相对目标直接交给 `os.path.islink(target)`，按**服务器进程 cwd** 解析 | `sub/a -> b`、`sub/b -> ../real` 时链只返回 `['b']`；真实解析应为 `/tmp/probe-link/real` | 相对目标按 `dirname(current)` 解析；环检测改用链接自身路径（避免 `a→b→real` 被 realpath 误判成环） |
| D3 | 服务器 cwd 被删除后返回非结构化异常 | 默认 cwd 直接 `os.getcwd()`，cwd 已 unlink 时抛 `OSError(ENOENT)` 冒到 MCP 层 | 返回 `Error executing tool execute_command: [Errno 2] No such file or directory`（客户端无法程序化分支） | `getcwd()` 失败回退 `/` 并加 note；若回退目录仍违反 `LCMD_ALLOWED_WORKDIRS`，抛结构化 `CWD_NOT_ACCESSIBLE` + “显式传 cwd”提示 |
| D4 | `notes` 在真实执行结果中被静默丢弃 | `ExecutionPlan` 有 `notes`，但 `ExecuteCommandOutput` 没有该字段，非 dry_run 分支也没传 | cwd 回退提示、风险级别提示、strict 限制提示只在 `dry_run.plan` 里能看到，真实调用永远拿不到 | `ExecuteCommandOutput.notes` 正式建模并在 dry_run/真实执行两条路径都透传 |
| D5 | `LCMD_PATH=""` 被当成“未设置” | 配置层 `path_raw not in (None, "")` 判断，把空字符串回退到进程 PATH | `LCMD_PATH=""` 时 `list_commands` 仍 `total=1890`，且 `scanned_dirs` 是进程 PATH 目录 | 改用“键是否存在”判断：空字符串＝不搜索任何 PATH 目录；文档同步该语义 |
| D6 | Bearer 认证 scheme 大小写敏感 | 直接与 `"Bearer <token>"` 整串比较 | `Authorization: bearer <token>` 对 `/sse` 返回 401（RFC 7235 要求 scheme 不区分大小写） | `partition(" ")` 拆 scheme，`scheme.lower()=="bearer"`，令牌仍 `compare_digest`；实测小写 → 200 |
| D7 | `Origin` 解析可被 userinfo 伪装绕过 | `_origin_host` 用字符串切分，`127.0.0.1:9999@evil.com` 被截成 `127.0.0.1` | `Origin: http://127.0.0.1:9999@evil.com` 时 SSE 流被放行（curl 挂住说明 200 已建立） | 改用 `urllib.parse.urlsplit`，userinfo 非空直接拒绝，按 `parsed.hostname` 比对；`http://[::1]:8765` 正确识别为回环；实测伪装来源 → 403 |
| D8 | 启动日志恒打 `(stdio)` | lifespan 文案写死，HTTP/SSE 模式也打印 `(stdio)`，误导排查 | SSE 启动日志出现 `MCP session started (stdio)` | 改为与传输无关的 `MCP session started` |
| D9 | 输出模型文档漏 `unrestricted` | `PolicySummary.mode` 描述只写 `strict / standard / permissive` | 默认档就是 `unrestricted`，但 schema 描述会误导模型以为该值非法 | 描述补齐四档 |
| D10 | 配置解析存在死代码 | `_absolute_dirs` 里 `if ":" in expanded ...: pass` 无任何作用 | 静态审计确认永远不生效，只增加阅读噪声 | 删除 |
| D11 | `list_commands` 描述与实现不符 | 描述称“PATH 为空返回空列表”，但实现默认还会并入标准目录 | 空 PATH 实测仍扫描 16 个标准/额外目录 | 描述改为“空 PATH 不报错，仍扫描标准目录；关闭 `LCMD_INCLUDE_DEFAULT_DIRS` 才可能为空” |
| D12 | `env` 键数 schema 上限（128）小于产品硬上限（256） | 输入模型与 `LCMD_MAX_ENV_KEYS` 硬上限不一致 | 运维把上限设为 256 时，128–256 个键仍会被参数守卫拒绝 | schema 上限对齐 256 |

---

## 3. 修复后验证（全部本轮实测）

| 验证项 | 命令 | 结果 |
|---|---|---|
| 单元/集成/协议/HTTP/参数守卫 | `python3 -m pytest -q` | **145 passed in ~31s** |
| 静态检查 | `python3 -m pyflakes src tests scripts examples` | 无输出 |
| 字节码编译 | `python3 -m compileall -q src scripts tests examples` | 通过 |
| 配置自检 | `python3 -m linux_cmd_mcp --check-config` | ok；transport=sse / 1818 命令 / 扫描 16 目录 |
| stdio 握手 | `python3 scripts/check_handshake.py` | **12/12 PASS** |
| HTTP/SSE 传输 | `python3 scripts/check_http_transport.py` | **20/20 PASS** |
| 29 条真实命令矩阵（2 轮） | `python3 scripts/check_e2e_tools.py` | **245 PASS / 0 FAIL** |
| 全机命令巡检 | `python3 scripts/check_all_commands.py --json reports/command_health.json` | 1818 名 / 1890 候选 / `broken={}` / `ok=73` / `skipped=1745` / 543ms |
| 稳定性压测 | `python3 scripts/check_stability.py` | **22/22 PASS**；60s 559 次调用 RSS 90184→90184 KB；SIGTERM 无 traceback/ERROR |

修复项的定向复测：

- 315 字符绝对路径：`execute_command` → `exit_code=0`（cwd=`/tmp`）。
- 相对符号链接链：`symlink_chain=['b','../real']`，`resolved_real_path=/tmp/probe-link/real`。
- 服务器 cwd 删除：默认 cwd 在允许范围内时回退 `/` 且 `notes` 含回退说明；受限时返回 `CWD_NOT_ACCESSIBLE`。
- `LCMD_PATH=""`：`total_matched=1721`，`scanned_dirs` 全部为标准目录，`skipped_dirs` 含 `('', skipped_empty)`。
- 小写 Bearer：`/sse` → 200；`Origin: http://127.0.0.1:9@evil.com` → 403。

---

## 4. 审计中确认“不是缺陷”的项

- 策略四档判定顺序与 `docs/POLICY.md` 一致：`permissive` 只拦 `HARD_DENY` + operator deny（`rm`/`sh` 放行、`sudo` 拒绝）；`standard`/`strict` 连 `rm`/`sudo`/`sh` 全拒；`unrestricted` 全放。
- `validate_working_directory` 对 `link -> /etc` 的越界链接返回 `outside_allowed_roots`；`execute_command` 同路径返回 `CWD_OUTSIDE_ALLOWED_ROOTS`，没有跟随链接逃逸。
- 客户端断开/取消后 `pgrep -x sleep` 无残留，服务器日志无 `Traceback` / `was destroyed` / `never retrieved`。
- `list_commands` 的 `directory="/usr/bin/"` 与 `/usr/bin` 结果一致（1373），不存在目录 `total=0`，`offset=99999` → `returned=0 / has_more=false`。
- `Origin: http://127.0.0.1.evil.com` 修复前后都正确 403（不是后缀匹配）。
- `unrestricted` 档允许 `LD_PRELOAD`/`PATH` 覆盖是文档明示的“等同 SSH 登录用户权限”设计，不按缺陷处理。

---

## 5. 已知边界（设计边界，不是错误）

| 边界 | 行为 | 依据 |
|---|---|---|
| `/usr/bin/xkeystone` | 可 `execve`，但运行期仍缺 `Nichrome` 库；apt/源码包均无该库 | `docs/COMMAND_HEALTH.md` 以“能 exec 即通过”为口径，不伪造 lib |
| 非回环绑定无令牌 | 启动即失败，退出码 64 | fail closed，避免裸奔 |
| TLS | 进程本身不终止 TLS，令牌是明文头 | 远程部署须由 nginx/caddy 终止 TLS |
| 回环 + 无令牌 | 本机任意进程可调用（默认配置） | 与 SSH 本地登录等价；要收紧就配 `LCMD_AUTH_TOKEN` |
| 命令覆盖 | 只覆盖“当前 PATH + 标准目录”里可发现的命令；不在 PATH 的二进制需 `LCMD_COMMAND_DIRS` 显式放行 | 不硬编码 `/bin`、`/usr/bin` 为唯一来源 |

---

## 6. 复现命令

```bash
cd /home/user/Doubao/chats/38453874755717890/linux-cmd-mcp

python3 -m pytest -q
python3 -m pyflakes src tests scripts examples
python3 -m linux_cmd_mcp --check-config
python3 scripts/check_handshake.py
python3 scripts/check_http_transport.py
python3 scripts/check_e2e_tools.py --rounds 2
python3 scripts/check_all_commands.py --json reports/command_health.json
python3 scripts/check_stability.py
```

对应回归用例：

- `tests/test_config.py::test_empty_path_override_is_respected`
- `tests/test_http_transport.py::test_bearer_scheme_is_case_insensitive`
- `tests/test_http_transport.py::test_origin_guard_rejects_userinfo_disguise_and_accepts_ipv6_loopback`
- `tests/test_tools.py::test_long_absolute_command_path_is_accepted`
- `tests/test_tools.py::test_symlink_chain_resolves_relative_targets`
- `tests/test_tools.py::test_execute_command_falls_back_when_server_cwd_disappears`
- `tests/test_tools.py::test_execute_command_reports_cwd_policy_after_fallback`
