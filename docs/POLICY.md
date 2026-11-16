# 策略、环境、传输与限额（唯一判定口径）

本文件是 `linux_cmd_mcp` 所有“能不能执行”“怎么连进来”判断的书面口径。代码里的唯一
实现点是 `src/linux_cmd_mcp/policy.py` 与 `src/linux_cmd_mcp/http_transport.py`；四个
查询/执行类工具共用同一份判定，避免 `check_command` 说能做、`execute_command` 却拒绝。

> 定位：`strict`/`standard`/`permissive` 是**护栏（guardrail）**，不是沙箱；`unrestricted`
> 干脆把护栏摘掉，等价于“一个 SSH 会话”。真正的隔离靠专用低权限用户 + 文件系统权限 +
> cgroups/seccomp/容器/SELinux。见 README「已知限制」。

## 1. 判定顺序（固定，先到先拒绝）

| # | 步骤 | 结果类别 | 生效档位 | 可否配置放开 |
|---|---|---|---|---|
| 1 | 命中 `HARD_DENY` | `hard_deny` | 除 `unrestricted` 外全部 | 否 |
| 2 | 绝对路径不在允许的命令目录内（仅在给了 `allowed_dirs` 时判定） | `path_forbidden` | 除 `unrestricted` 外全部 | 是，`LCMD_COMMAND_DIRS` |
| 3 | 命中 `LCMD_DENYLIST` | `operator_deny` | **全部档位（含 unrestricted）** | 是，从 `LCMD_DENYLIST` 移除 |
| 4 | `unrestricted` 直接放行 | `unrestricted` | — | — |
| 5 | 按档位判定 | `strict_not_allowlisted` / `soft_deny` / 放行 | 非 unrestricted | 见第 2 节 |

`LCMD_DENYLIST` 是唯一在 `unrestricted` 下仍然生效的拒绝规则——这是有意设计：完全放开
的档位也必须留一个“运维说不行”的开关。

## 2. 四种档位

| 档位 | 放行 | 拒绝 | 典型用途 |
|---|---|---|---|
| `unrestricted`（**默认**） | 一切命令（含 `sudo`/`rm`/`dd`/`bash`）、任意绝对路径可执行文件 | 仅 `LCMD_DENYLIST` | 把整台机器交给模型，等价 SSH 会话 |
| `permissive` | 未被硬拒绝/显式拒绝的命令 | `HARD_DENY` ∪ `LCMD_DENYLIST` | 受控实验：允许 `rm` 等破坏性命令 |
| `standard` | 未被软拒绝/shell 类/显式拒绝的命令 | `SOFT_DENY` ∪ shell/包装器 ∪ `LCMD_DENYLIST` | 日常运维：可读、可跑构建，禁删除与提权 |
| `strict` | `BUILTIN_SAFE`（83 个只读命令）∪ `LCMD_ALLOWLIST` | 其余全部 | 只让模型读系统状态 |

补充规则：

- `unrestricted` 下 `PolicyEngine` 的软拒绝表为空、`HARD_DENY` 不参与判定、
  绝对路径目录限制被跳过，`matched_rule` 恒为 `unrestricted`；启动时打一条 WARNING。
- `LCMD_DENYLIST_OVERRIDE=1` 只在非 `unrestricted` 档位有意义：用 `LCMD_DENYLIST`
  **替换**内置软名单（`HARD_DENY` 仍在）。`unrestricted` 下软名单已经为空，该开关无副作用。
- `strict` 模式 `LCMD_ALLOWLIST` 优先于内置集判断，但**不能**绕过 `HARD_DENY`。
- `LCMD_ALLOWLIST` 与 `LCMD_DENYLIST` 出现同名条目在启动期直接 `ConfigError`（拒绝优先，语义不许含糊）。

### 2.1 `unrestricted` 的安全边界（必读）

`unrestricted` 的权限边界 = **运行本服务器的那个 Linux 用户**。它自己不做任何限制，
所以真正的边界必须由外部提供：

1. **别用 root 跑**。用专用用户（例如 `lcmd`）启动，再用 `sudoers` 精确授权需要的命令；
   否则模型能改 `/etc/shadow`、装内核模块、重启机器。
2. **HTTP/SSE 必须带令牌**。绑定非回环地址且没有 `LCMD_AUTH_TOKEN` 时 `serve_http`
   直接抛 `ConfigError`（fail closed，退出码 64）。
3. **远程要 TLS**。令牌走 HTTP 头明文传输，跨网段必须在前置 nginx/caddy 终止 TLS。
4. **审计**。`LCMD_LOG_LEVEL=INFO` 会把每次调用（命令、argv、cwd、exit_code）记到 stderr，
   建议接 journald 保留。

## 3. 内置名单

### 3.1 硬拒绝 `HARD_DENY`（53 个，`unrestricted` 之外任何档位不可放行）

| 组别 | 命令 |
|---|---|
| 提权 / 命名空间逃逸（9） | `sudo` `su` `doas` `pkexec` `nsenter` `unshare` `setpriv` `capsh` `chroot` |
| 内核模块（4） | `insmod` `rmmod` `modprobe` `depmod` |
| 磁盘 / 文件系统破坏（12） | `dd` `mkfs` `mke2fs` `mkswap` `fdisk` `cfdisk` `gdisk` `sgdisk` `parted` `wipefs` `blkdiscard` `shred` |
| 挂载与交换区（4） | `mount` `umount` `swapon` `swapoff` |
| 系统电源（6） | `halt` `poweroff` `reboot` `shutdown` `init` `telinit` |
| 账号管理（8） | `useradd` `userdel` `usermod` `groupadd` `groupdel` `passwd` `chpasswd` `visudo` |
| 防火墙（5） | `iptables` `ip6tables` `nft` `ufw` `firewall-cmd` |
| 容器运行时（2） | `docker` `podman` |
| 系统内核/库调参（2） | `sysctl` `ldconfig` |
| 服务控制（1） | `systemctl` |

### 3.2 软拒绝 `SOFT_DENY`（14 个，`standard` 默认拒绝）

`rm` `rmdir` `unlink` `chmod` `chown` `chgrp` `setfacl` `setcap` `kill` `pkill` `killall`
`crontab` `at` `batch`

### 3.3 shell 与包装器（24 个，`standard` 默认拒绝）

- shell（11）：`sh` `bash` `dash` `zsh` `ksh` `mksh` `csh` `tcsh` `fish` `busybox` `toybox`
- 包装器（13）：`env` `xargs` `nohup` `setsid` `script` `expect` `timeout` `watch`
  `parallel` `runuser` `strace` `ltrace` `gdb`

拒绝理由：它们都会**绕过“命令与参数分离”的契约**——`bash -c` 等于把 shell 交还调用方，
`xargs`/`env` 能把任意字符串变成新进程的 argv。`category=shell_wrapper`。
`unrestricted` 下这些全部放行（模型本来就能随便跑 `bash -c`），需要时切 `standard` 收回。

### 3.4 严格模式只读集 `BUILTIN_SAFE`（83 个）

包含 `ls` `cat` `grep` `rg` `find` `stat` `file` `head` `tail` `wc` `sort` `cut` `tr` `diff` `cmp`
`ps` `ss` `lsof` `df` `du` `free` `lscpu` `lsblk` `uname` `hostname` `id` `whoami` `groups`
`journalctl` `dmesg` `git` `python3` `jq` `yq` 以及各类校验和（`sha256sum`/`md5sum`）等 83 项。
完整清单以 `policy.py` 的 `BUILTIN_SAFE` 常量为准（唯一事实来源，文档不复制以免漂移）。

> `BUILTIN_SAFE` 里的 `find`/`python3`/`git` 仍可间接执行任意命令（`-exec`、`-c`、`alias`）。
> 严格模式的意义是“默认不给你破坏性工具”，不是“保证不产生副作用”。

## 4. 风险分类

`risk` 取 8 个值之一：`read_only`、`mutating`、`network`、`process_control`、
`privileged`、`destructive`、`shell_wrapper`、`unknown`。
`category` 是更细的类别（29 种），例如 `archive`、`package_manager`、`vcs`、`scheduler`、
`file_delete`、`permission_change`、`disk_destroy`、`http`、`remote_shell`。
`RISK_TABLE` 覆盖 251 个常见命令；表外命令一律 `unknown`（不猜测，不猜成“安全”）。

## 5. 绝对路径、符号链接与可执行性

- 命令解析：裸名按 PATH 顺序逐个目录查找，命中第一个**可执行**文件即 `resolved_path`，
  同时保留全部同名候选（`path_index` 记录 PATH 序号，`shadowed` 标记被更高优先级遮蔽的候选）。
- 符号链接：不展开用于匹配，但会记录 `real_path` 与逐级 `readlink` 链（`describe_command.symlink_chain`）。
- 权限判定用 `os.access(X_OK)`（对 root 恒真，这是 POSIX 语义，不做特殊处理）。
- 目录限制用 `os.path.commonpath` 语义的 `is_inside`，`/tmp/a` 不会匹配 `/tmp/ab`。
- 虚拟文件系统 `/proc`、`/sys`、`/dev` 永远不扫描（避免把内核接口当命令目录）。

### 5.1 可执行性判定（`executability`）

`os.access(X_OK)` 只说明有执行位，不代表 `execve` 会成功。`check_command` 与
`describe_command` 额外用 `exec_probe.probe_executability()` 做**不启动进程**的静态解析：

| 检查项 | 失败原因（`executability.reason`） | 内核错误 |
|---|---|---|
| `stat` 成功、是普通文件、有 x 位 | 缺一项都判不可运行 | `ENOENT`/`EACCES` |
| ELF `PT_INTERP` 动态加载器存在且可执行 | `缺失动态加载器 …` | `ENOENT` |
| ELF `e_machine` 与宿主架构一致 | `架构不匹配：程序 i386，宿主 x86_64` | `ENOEXEC`/`ENOENT` |
| 脚本 `#!` 解释器存在且可执行 | `shebang 解释器不存在 …` | `ENOENT` |
| `#!/usr/bin/env NAME` 能在 PATH 找到 NAME | `/usr/bin/env 找不到解释器 'nickle'` | `ENOENT` |
| shebang 行无 CR | `shebang 行含 CR …（bad interpreter）` | `ENOENT` |
| 非 ELF 必须有 shebang | `既不是 ELF 也没有 shebang` | `ENOEXEC` |

`list_commands` 的 `runnable=true|false` 用同一解析结果过滤（`runnable=false`
即“起不来的命令”），每条候选带 `runnable` 与 `unrunnable_reason`。
`execute_command` 在启动前也会做同一判定：不可运行时直接返回
`COMMAND_NOT_EXECUTABLE`，details 里给 `kind`/`interpreter`/`reason`，
而不是等 `execve` 报一个含混的 `ENOENT`。

## 6. 环境变量

子进程环境 =「基础白名单透传」+「调用方 overrides」。

**基础透传白名单 `BASE_ENV_ALLOWED`（21）——任何档位都只透传这些**

`PATH` `HOME` `LANG` `LANGUAGE` `LC_ALL` `LC_CTYPE` `LC_MESSAGES` `LC_NUMERIC` `LC_TIME`
`LC_COLLATE` `TERM` `TZ` `TZDIR` `USER` `LOGNAME` `TMPDIR` `SHELL` `COLUMNS` `LINES`
`NO_COLOR` `FORCE_COLOR`

> 有意**不**把服务器进程的全部环境（可能含 `AWS_*`、`GITHUB_TOKEN`、数据库口令）透传给
> 子进程。`unrestricted` 放开的是“调用方能设哪些键”，不是“把服务器密钥送给子进程”。

**调用方 overrides 按档位**

| 档位 | `env` 行为 |
|---|---|
| `unrestricted` | 任意合法键都允许（含 `LD_PRELOAD`、`PATH` 覆盖），只做形状校验 |
| `strict` / `standard` / `permissive` | 只允许 `ENV_OVERRIDE_DENIED` 之外的键；白名单外键需 `LCMD_ENV_ALLOWLIST_EXTRA` 登记；**不允许覆盖 `PATH`** |

**注入类拒绝 `ENV_DENIED`（48，包含 `ENV_OVERRIDE_DENIED` 49 项含 `PATH`）**

`LD_PRELOAD` `LD_LIBRARY_PATH` `LD_AUDIT` `LD_DEBUG` `LD_DEBUG_OUTPUT` `LD_ORIGIN_PATH`
`LD_PROFILE` `DYLD_INSERT_LIBRARIES` `DYLD_LIBRARY_PATH` `GLIBC_TUNABLES` `MALLOC_CONF`
`LOCPATH` `NLSPATH` `PYTHONPATH` `PYTHONHOME` `PYTHONSTARTUP` `PYTHONINSPECT`
`PYTHONEXECUTABLE` `NODE_OPTIONS` `NODE_PATH` `PERL5LIB` `PERLLIB` `RUBYLIB` `RUBYOPT`
`JAVA_TOOL_OPTIONS` `_JAVA_OPTIONS` `BASH_ENV` `ENV` `BASHOPTS` `SHELLOPTS` `PROMPT_COMMAND`
`PS4` `IFS` `CDPATH` `GLOBIGNORE` `GIT_ASKPASS` `GIT_SSH_COMMAND` `GIT_EXTERNAL_DIFF`
`SSH_ASKPASS` `SSLKEYLOGFILE` `LESSOPEN` `LESSCLOSE` `PAGER` `EDITOR` `VISUAL` `BROWSER`
`TEMP` `TMP`

**与档位无关、永远生效的形状校验**

- 键名必须匹配 `^[A-Za-z_][A-Za-z0-9_]*$`，否则 `ENV_KEY_FORBIDDEN`。
- 值必须是字符串、不含 NUL、不超过 8192 字节，否则 `ENV_VALUE_INVALID`。
- 键数量受 `LCMD_MAX_ENV_KEYS`（默认 32）限制，超限 `LIMIT_EXCEEDED`。

> `unrestricted` 下允许改 `PATH` 的语义：`env.PATH` 只影响**子进程内部**的查找
> （例如它自己 `exec` 别的东西）；服务器解析 `command` 用的是发现用的 PATH。

## 7. 限额与超时（超限即拒绝，不静默截断为合法值）

| 项目 | 默认 | 可配置上限（`LCMD_*`） | 代码硬上限 |
|---|---|---|---|
| 单次 timeout | 20s（`default`） | 60s（`max`） | 3600s |
| `max_output_bytes`（stdout/stderr **各自**） | 1 MiB | 1 MiB | 32 MiB |
| `stdin` 字节 | 1 MiB | 1 MiB | 4 MiB |
| `args` 元素数 | — | 256 | 1024 |
| 单个 argv 元素字符数 | — | 4096 | 65536 |
| 额外 env 键数 | — | 32 | 256 |
| 并发执行 | — | 4 | 32 |
| `list_commands.limit` | 100 | 2000 | — |

规则细节：

- 请求里的 `timeout_seconds` 超过「服务端上限」→ `LIMIT_EXCEEDED` 拒绝，**不 clamp**。
  （悄悄缩短会让调用方以为自己的 5 分钟任务成功跑完了。）
- `max_output_bytes` 同理：超过上限拒绝。
- 输出超限不拒绝：stdout/stderr 各自保留前 N 字节，其余继续读取但丢弃，
  同时给出 `stdout_bytes`/`stderr_bytes`（真实总量）与 `truncated`。
  必须继续读，否则管道写满会把子进程卡死。
- argv 总长另有 128 KiB 兜底（防止 execve E2BIG）。
- **默认超时与上限的耦合**：若只调小 `LCMD_MAX_TIMEOUT_SECONDS`（例如 10），
  未显式设置 `LCMD_DEFAULT_TIMEOUT_SECONDS` 时默认值会自动夹到上限（10），
  服务器正常启动；若显式写了 `LCMD_DEFAULT_TIMEOUT_SECONDS=20` 又小于上限冲突，
  则启动期 `ConfigError`（不静默改你写死的值）。

## 8. 工作目录状态机（`validate_working_directory` / `execute_command.cwd`）

| status | 含义 | `usable_as_cwd` |
|---|---|---|
| `ok` | 存在、是目录、可读、可搜索、在允许根内、（若要求）可写 | true |
| `not_found` | 路径不存在 | false |
| `not_a_directory` | 存在但不是目录 | false |
| `permission_denied` | 无读或无搜索权限 | false |
| `not_writable` | `require_write=true` 但不可写 | false |
| `outside_allowed_roots` | 未命中 `LCMD_ALLOWED_WORKDIRS` | false |
| `not_accessible` | 路径无法访问（如父目录不可搜索、挂载失效） | false |
| `invalid_path` | 空、含 NUL、超长、无法规范化 | false |

`LCMD_ALLOWED_WORKDIRS` 为空表示**不限制**；一旦配置，`execute_command` 的默认 cwd
（服务器进程当前目录）也必须落在其中，否则会被 `CWD_OUTSIDE_ALLOWED_ROOTS` 拒绝——
把服务器进程的 cwd 放进允许根是部署时的必做项。

## 9. 传输与鉴权

| 传输 | 端点 | 适用 |
|---|---|---|
| `sse`（**默认**） | `GET /sse` 事件流 + `POST /messages/` 上行 | 常驻服务、远程宿主/IDE，兼容性最好 |
| `streamable-http` | 单端点 `POST/GET /mcp` | 新版规范推荐的远程传输，支持会话续传 |
| `stdio` | 进程 stdin/stdout | 本地宿主把服务器当子进程（Claude Desktop 等） |

鉴权与网络面（`http_transport.py`）：

1. 配置 `LCMD_AUTH_TOKEN`（≥16 字符）后，除 `GET /healthz` 外**所有**请求都要
   `Authorization: Bearer <token>`；scheme 按 RFC 7235 大小写不敏感
   （`bearer` / `BeArEr` 均可），令牌比较用 `hmac.compare_digest`（固定时间）。
   失败 401 + `WWW-Authenticate`。
2. 带 `Origin` 头的请求只允许 `LCMD_ALLOWED_ORIGINS` 里列出的来源，或回环来源
   （`http://127.0.0.1:*`、`http://localhost:*`），否则 403（防 DNS rebinding）。
   无 `Origin` 的非浏览器客户端正常放行。`Origin` 带 userinfo（`http://127.0.0.1:9999@evil.com`）
   或无法解析为主机名时一律 403，避免用字符串截断造成绕过。
3. 绑定非回环地址且无令牌 → `ConfigError`，进程退出码 64（fail closed，不“先跑起来再说”）。
4. 中间件顺序：Origin 校验在最外层（先 403，再谈鉴权），鉴权次之，SDK 应用最内层。
5. `GET /healthz` 免鉴权，只回 `{status, transport, auth_enabled, policy_mode}`，
   不含任何命令、路径、令牌信息。
6. 远程部署时令牌在 HTTP 头明文传输，**必须**在前置 nginx/caddy 终止 TLS；
   建议用 systemd 常驻并限制 `ListenStream` 到内网地址。

## 10. 错误码（业务错误一律 `isError: true` + JSON 负载）

| code | 触发场景 | 建议动作 |
|---|---|---|
| `INVALID_ARGUMENT` | 参数非法：schema 级违规（`limit=0`、`timeout_seconds>3600`、`max_output_bytes=0`）、未知/拼错字段（`timout_seconds`）、参数语义非法（空命令名、含 NUL、相对路径等）。协议边界先做一次模型校验，**不会**把 SDK 的英文 pydantic 文本漏出去 | 按 `error.details.fields`（`field`/`error`/`type`）逐项修正入参 |
| `COMMAND_NOT_FOUND` | PATH 中找不到可执行文件 | 用 `list_commands` / `check_command` 探路 |
| `COMMAND_NOT_EXECUTABLE` | 命中文件但无 x 位，或静态解析判定 execve 必失败（缺解释器/加载器/架构不符/无 shebang/CRLF） | 看 `details.kind`/`details.interpreter`/`details.reason`，修解释器或换候选 |
| `COMMAND_PATH_FORBIDDEN` | 绝对路径不在允许目录 | 加 `LCMD_COMMAND_DIRS` |
| `POLICY_DENIED` | 命中硬拒绝/软拒绝/显式拒绝/路径限制 | 看 `details.category`、`details.matched_rule` |
| `CWD_NOT_FOUND` | cwd 不存在 | 先建目录 |
| `CWD_NOT_A_DIRECTORY` | cwd 是文件 | 换目录 |
| `CWD_PERMISSION_DENIED` | cwd 不可读/搜索 | 修权限 |
| `CWD_OUTSIDE_ALLOWED_ROOTS` | cwd 不在允许根 | 调 `LCMD_ALLOWED_WORKDIRS` |
| `CWD_NOT_ACCESSIBLE` | 路径无法访问 | 检查挂载/父目录权限 |
| `ENV_KEY_FORBIDDEN` | env 键名非法，或非 `unrestricted` 档位下不在白名单/在拒绝表/试图改 PATH | 用 `LCMD_ENV_ALLOWLIST_EXTRA`，或切 `unrestricted` |
| `ENV_VALUE_INVALID` | env 值非法（NUL、非字符串、超长） | 修正值 |
| `LIMIT_EXCEEDED` | timeout/输出/args/env/stdin 超限 | 收敛请求或调上限 |
| `SPAWN_FAILED` | fork/exec 失败（资源不足、E2BIG 等） | 看 `details.errno` |
| `TIMEOUT` | 超时（同时 `timed_out=true` 出现在输出里） | 缩短任务或调 `LCMD_MAX_TIMEOUT_SECONDS` |
| `CANCELLED` | 客户端 `notifications/cancelled` 中断 | 无需处理，进程组已回收 |
| `INTERNAL_ERROR` | 未预期异常（已记 stderr） | 报 issue，附 traceback |

两条边界实现（与上表配套）：

1. **参数守卫**：`install_argument_guard()` 包住 `CallToolRequest` 处理器，先按
   `INPUT_MODELS`（`tools/_flat.py` 在注册时填充的 tool→模型表）校验原始
   `arguments`，`ValidationError` 直接转成 `INVALID_ARGUMENT`，`details.tool` 与
   `details.fields` 最多 5 项；校验通过才交回 SDK。因此能同时拦住 schema 违规与
   `extra="forbid"` 的多余字段（SDK 默认会静默忽略多余字段）。
2. **`stdin` 原样透传**：SDK `FuncMetadata.pre_parse_json` 原本会对“注解不是 `str`”
   的参数做 `json.loads`，让 `stdin='{"a": 1}'` 被转成 dict 再被 `str` 校验拒掉。
   `install_sdk_compat()` 只在**非字符串字段**保留该宽松解析（兼容宿主把数组当
   JSON 字符串传），字符串字段（`stdin`、`command` 等，含 `str | None`）一律
   原样交给子进程。

负载形状（`standard` 档位下拒绝 `rm`）：

```json
{
  "ok": false,
  "error": {
    "code": "POLICY_DENIED",
    "message": "rm 默认拒绝（递归/批量删除不可逆）；需要时由运维调整 LCMD_DENYLIST。",
    "hint": "用 check_command 确认策略状态，或由运维调整 LCMD_ALLOWLIST / LCMD_DENYLIST。",
    "details": {"command": "rm", "path": "/usr/bin/rm", "risk": "destructive",
                 "category": "file_delete", "matched_rule": "soft_deny:rm",
                 "policy_mode": "standard"}
  }
}
```

FastMCP 会把异常包装成 `Error executing tool <name>: <我们的 JSON>`，客户端应从
**第一个 `{` 起**解析。纯 schema 级校验失败（如 `limit=0`）由 SDK 直接产生
`isError: true`，文本是 pydantic 校验信息，不是上面的 JSON——见 README「错误约定」。

## 11. 全部 `LCMD_*` 变量

| 变量 | 含义 | 默认 |
|---|---|---|
| `LCMD_POLICY_MODE` | `unrestricted` / `permissive` / `standard` / `strict` | `unrestricted` |
| `LCMD_AUTH_TOKEN` | HTTP/SSE 的 Bearer 令牌（≥16 字符，禁空白/NUL） | 空＝仅允许绑回环地址 |
| `LCMD_HTTP_HOST` | SSE / Streamable HTTP 监听地址 | `127.0.0.1` |
| `LCMD_HTTP_PORT` | SSE / Streamable HTTP 监听端口 | `8765` |
| `LCMD_ALLOWED_ORIGINS` | 允许的 `Origin` 来源（逗号分隔，额外于回环） | 空 |
| `LCMD_INCLUDE_DEFAULT_DIRS` | 是否并入标准命令目录一起扫描 | `1` |
| `LCMD_ALLOWLIST` | 额外放行命令（逗号/分号/空白分隔） | 空 |
| `LCMD_DENYLIST` | 额外拒绝命令（**所有档位生效**） | 空 |
| `LCMD_DENYLIST_OVERRIDE` | 置 1 时用 `LCMD_DENYLIST` 替换内置软名单 | `0` |
| `LCMD_ALLOWED_WORKDIRS` | 允许作为 cwd 的绝对路径根（逗号分隔） | 空＝不限制 |
| `LCMD_COMMAND_DIRS` | 额外允许绝对路径执行的绝对目录 | 空 |
| `LCMD_PATH` | 覆盖用于命令发现的 PATH；**空字符串＝不搜索 PATH 目录**（标准目录仍按 `LCMD_INCLUDE_DEFAULT_DIRS` 并入） | 进程 PATH |
| `LCMD_MAX_TIMEOUT_SECONDS` | 单次执行超时上限 | `60` |
| `LCMD_DEFAULT_TIMEOUT_SECONDS` | 未传 `timeout_seconds` 时的默认值；**未显式设置时会随 `LCMD_MAX_TIMEOUT_SECONDS` 夹取**，显式设置且高于上限则报错 | `20` |
| `LCMD_MAX_OUTPUT_BYTES` | stdout/stderr 各自保留字节上限 | `1048576` |
| `LCMD_MAX_STDIN_BYTES` | stdin 字节上限 | `1048576` |
| `LCMD_MAX_ARGS` | argv 元素上限 | `256` |
| `LCMD_MAX_ARG_LENGTH` | 单个 argv 元素字符上限 | `4096` |
| `LCMD_MAX_ENV_KEYS` | 额外 env 键上限 | `32` |
| `LCMD_MAX_CONCURRENCY` | 并发执行上限 | `4` |
| `LCMD_DISCOVERY_TTL_SECONDS` | 命令发现缓存 TTL（0＝每次重扫） | `5` |
| `LCMD_ALLOW_STDIN` | 是否允许传 `stdin` | `true` |
| `LCMD_ENV_ALLOWLIST_EXTRA` | 额外允许透传的 env 键 | 空 |
| `LCMD_LOG_LEVEL` | 日志级别（**只写 stderr**） | `WARNING` |

所有变量在启动期一次性读取并校验，`LCMD_MAX_TIMEOUT_SECONDS` 调小时默认超时自动夹到上限
（例如 `LCMD_MAX_TIMEOUT_SECONDS=10` → `default=10`），只有**显式**写了冲突值才报错，非法值直接 `ConfigError`（退出码 64，信息写 stderr），
不做运行时静默降级。

## 12. 已知边界（写在这里避免被误当成漏洞）

1. `unrestricted` 不是沙箱，它就是“以服务器进程的用户身份跑命令”。别用 root 跑。
2. `standard`/`strict` 也不是沙箱：`find -exec`、`python3 -c`、`make`/`git hook`、
   `crontab` 之外的间接执行链都能绕过命令级判定。
3. `os.access` 对 root 恒真：以 root 运行时“无执行权限”类判定不生效。
4. 非 `unrestricted` 档位不支持 `LD_PRELOAD` 等注入类变量，也不支持调用方改 PATH——
   这是**有意**的能力缺失；`unrestricted` 下放开。
5. 无鉴权 + 绑回环时，本机任意进程都能调用（本机信任模型）；跨机访问必须配令牌 + TLS。
6. 宿主机上确实存在“装上了但缺依赖”的命令（本机实测：`/usr/bin/xkeystone` 的
   shebang 需要未安装的 `nickle`）。本服务器只**如实报告**不可运行，不会替发行版
   装依赖；修复它属于系统包变更，命令见 `docs/COMMAND_HEALTH.md`。
