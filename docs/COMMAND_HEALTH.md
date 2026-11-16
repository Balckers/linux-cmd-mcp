# 全系统命令可用性巡检报告

生成方式：`python3 scripts/check_all_commands.py --json reports/command_health.json`
（报告时间 2026-11-15，主机 = 本云主机，策略档位 = `unrestricted`）。

本轮已先补齐系统依赖：`sudo apt-get update -qq && sudo apt-get install -y -qq nickle`
（`nickle 2.91`）。

## 1. 结论

| 指标 | 实测值 |
|---|---|
| 扫描目录 | 25 条扫描项（16 实际扫描 / 8 `duplicate` / 1 `missing`） |
| 命令名 | **1818** |
| 候选路径（同名多目录） | **1890** 行 |
| 静态解析后真能 exec | **1890** 行 |
| 起不来（`broken`） | **0** |
| 只读命令真实启动探针 | 73 个全部 `ok`（任意退出码都算启动成功） |
| `--help` 挂死（`hang`） | 0 |
| 全量巡检耗时 | 445 ms |

> 静态解析口径：ELF 的 `PT_INTERP` 动态加载器是否存在且可执行、`e_machine` 是否与宿主
> 架构一致、脚本 `#!` 解释器是否存在（含 `#!/usr/bin/env NAME` 走 PATH 解析）、
> shebang 是否被 CRLF 污染、文件是否有 x 位、是否为普通文件。不启动进程。

## 2. 曾经的唯一坏命令：`/usr/bin/xkeystone`（已修到能 exec）

`x11-xserver-utils` 带的 `/usr/bin/xkeystone` 首行是 `#!/usr/bin/env nickle`，
而本机原先没装 `nickle`，`execve` 直接 `ENOENT`。补装 `nickle` 后：

```
/usr/bin/xkeystone
  probe:  runnable=true, interpreter=/usr/bin/nickle
  实跑:   Cannot autoload from file "nichrome.5c"
          call to undefined function: ...  (non-existant namespace Nichrome)
```

第二层是**上游脚本自身的运行时依赖**：它需要一个叫 `Nichrome` 的 Nickle 库
（`/usr/share/nickle` 只有 26 个标准库，没有 `nichrome*`）。核查结论：

- `apt-cache search nichrome` → 空；
- Debian/Ubuntu 源码包（`x11-xserver-utils` 7.7+3 / +7 / +8 / +9 / +11）全部**不含**
  `xkeystone` 目录；
- 本机没有 X display，这个脚本即便跑起来也无实际用途。

因此这是**发行版遗留的僵尸脚本**，不是本项目缺陷，也没有可安装的补齐包。
本报告的口径是：**静态 + `execve` 能起来即计入可用**（`broken=0`），
运行期缺库作为已知限制如实记录在此，不伪装为成功。

## 3. 判定口径（为什么不是“看存在就算可用”）

`os.access(X_OK)` 只说明有执行位。以下情况会让 `execve` 失败，而 `ls` 看起来一切正常：

| 现象 | 内核返回 | 为什么 |
|---|---|---|
| 悬空符号链接 / 目标被删 | `ENOENT` | 解析后目标不存在 |
| `#!/usr/bin/env python2` 但没装 python2 | `ENOENT` | 解释器本身找不到 |
| `#!/bin/sh\r`（CRLF） | `ENOENT` | `\r` 被算进解释器路径（经典 bad interpreter） |
| ELF 的 `PT_INTERP` 指向不存在的加载器 | `ENOENT` | 动态链接器缺失（典型：32 位库未装） |
| `e_machine` 与宿主架构不符 | `ENOEXEC` / `ENOENT` | 需要对应 emulator/多架构库 |
| 无 `#!` 的文本文件 | `ENOEXEC` | 内核不认这种可执行格式 |
| 有 x 位但挂载 `noexec` | `EACCES` | 文件系统层面禁止执行 |

所以 `check_command` / `describe_command` 在“有执行位”之外，额外给出
`executability`（`kind` / `runnable` / `reason` / `interpreter` / `elf_class` /
`elf_machine` / `notes`）；`list_commands` 支持 `runnable=true|false` 直接把
“起不来的命令”筛出来（本机实测：`runnable=false` 命中 0 行、`runnable=true` 1890 行，
一次全量解析约 130 ms）。

## 4. 复现步骤

```bash
cd /home/user/Doubao/chats/38453874755717890/linux-cmd-mcp

# 只做静态解析（不启动任何命令，秒级）
python3 scripts/check_all_commands.py --no-exec

# 全量（只读命令会真跑一次 --help）
python3 scripts/check_all_commands.py

# 机器可读报告
python3 scripts/check_all_commands.py --json reports/command_health.json

# 单个命令复核
python3 - <<'PY'
from linux_cmd_mcp.exec_probe import probe_executability
print(probe_executability("/usr/bin/xkeystone"))
PY
```

退出码：`0` = 无 broken；`1` = 有 broken（会按原因分组打印）。

## 依赖自愈（环境重建）

云主机/容器重建会清空 apt 安装包，`nickle` 消失会让 `/usr/bin/xkeystone` 退化为
`missing_interpreter`（broken 由 0 变 1）。跑一次幂等脚本即可恢复：

```bash
bash scripts/bootstrap_deps.sh            # 安装并复核 execve
bash scripts/bootstrap_deps.sh --check-only  # 只检查不安装（部署前 gate）
```
