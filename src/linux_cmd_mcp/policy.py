"""执行策略层：命令放行/拒绝、风险分类、环境变量与参数校验。

这是所有“能不能执行”判断的唯一实现点。四个工具都复用同一份判定，
避免 ``check_command`` 说能做、``execute_command`` 却拒绝。

优先级（模式无关，永远第一）
---------------------------
1. ``HARD_DENY``：提权、内核模块、磁盘分区/格式化、系统电源、账号管理、
   防火墙、容器运行时。**任何模式都无法放行**，也不受 LCMD_DENYLIST 影响。

之后按模式
----------
* ``unrestricted``（默认）：只拒绝 ``LCMD_DENYLIST`` 显式列出的命令，其余全部放行；
                  不施加硬拒绝、软拒绝、shell 包装器与命令目录限制。等价于“SSH 会话
                  的权限边界 = 运行本服务器的 Linux 用户”，用于把整台机器交给模型控制。
                  这是**显式放弃护栏**的档位，启动会打 WARNING。
* ``strict``    ：放行 ``BUILTIN_SAFE``（内置只读安全集）∪ ``LCMD_ALLOWLIST``；
                  其余全部拒绝；``LCMD_DENYLIST`` 只用于追加拒绝（无实际作用）。
* ``standard``  ：拒绝 ``SOFT_DENY`` ∪ ``LCMD_DENYLIST``；其余放行。
                  ``LCMD_DENYLIST_OVERRIDE=1`` 时用 ``LCMD_DENYLIST`` 替换
                  内置 ``SOFT_DENY``（``HARD_DENY`` 仍在）。
* ``permissive``：只拒绝 ``HARD_DENY`` ∪ ``LCMD_DENYLIST``；其余放行。

注意：这是护栏（guardrail），不是沙箱。它无法阻止 ``find -exec``、
``python -c``、``git alias`` 等间接执行；真正的隔离要靠专用低权限用户、
cgroups/seccomp/容器或 selinux/apparmor。README 的“已知限制”对此有说明。
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .config import Settings
from .errors import ErrorCode, fail

SHELL_COMMANDS = frozenset(
    {"sh", "bash", "dash", "zsh", "ksh", "mksh", "csh", "tcsh", "fish", "busybox", "toybox"}
)
WRAPPER_COMMANDS = frozenset(
    {"env", "xargs", "nohup", "setsid", "script", "expect", "timeout", "watch", "parallel", "runuser", "strace", "ltrace", "gdb"}
)

#: 硬拒绝：无法通过任何配置放行。值为 (类别, 风险, 说明)
HARD_DENY: dict[str, tuple[str, str, str]] = {
    # 提权 / 命名空间逃逸
    "sudo": ("privilege_escalation", "privileged", "提权工具"),
    "su": ("privilege_escalation", "privileged", "切换用户"),
    "doas": ("privilege_escalation", "privileged", "提权工具"),
    "pkexec": ("privilege_escalation", "privileged", "提权工具"),
    "nsenter": ("privilege_escalation", "privileged", "可进入其它命名空间"),
    "unshare": ("privilege_escalation", "privileged", "可创建命名空间绕过隔离"),
    "setpriv": ("privilege_escalation", "privileged", "权限位操作"),
    "capsh": ("privilege_escalation", "privileged", "capability 操作"),
    "chroot": ("privilege_escalation", "privileged", "改变根目录"),
    # 内核模块
    "insmod": ("kernel_modules", "privileged", "加载内核模块"),
    "rmmod": ("kernel_modules", "privileged", "卸载内核模块"),
    "modprobe": ("kernel_modules", "privileged", "加载/卸载内核模块"),
    "depmod": ("kernel_modules", "privileged", "模块依赖处理"),
    # 磁盘 / 文件系统
    "dd": ("disk_destroy", "destructive", "可覆写任意块设备"),
    "mkfs": ("disk_destroy", "destructive", "格式化文件系统"),
    "mke2fs": ("disk_destroy", "destructive", "格式化文件系统"),
    "mkswap": ("disk_destroy", "destructive", "创建 swap 区"),
    "wipefs": ("disk_destroy", "destructive", "擦除文件系统签名"),
    "blkdiscard": ("disk_destroy", "destructive", "丢弃块设备数据"),
    "fdisk": ("disk_destroy", "destructive", "分区表编辑"),
    "parted": ("disk_destroy", "destructive", "分区表编辑"),
    "sgdisk": ("disk_destroy", "destructive", "分区表编辑"),
    "gdisk": ("disk_destroy", "destructive", "分区表编辑"),
    "cfdisk": ("disk_destroy", "destructive", "分区表编辑"),
    "shred": ("disk_destroy", "destructive", "覆写文件内容"),
    "mount": ("mount_control", "privileged", "挂载文件系统"),
    "umount": ("mount_control", "privileged", "卸载文件系统"),
    "swapon": ("mount_control", "privileged", "启用 swap"),
    "swapoff": ("mount_control", "privileged", "关闭 swap"),
    # 系统电源 / 服务
    "shutdown": ("system_power", "destructive", "关机"),
    "reboot": ("system_power", "destructive", "重启"),
    "poweroff": ("system_power", "destructive", "关机"),
    "halt": ("system_power", "destructive", "停机"),
    "init": ("system_power", "destructive", "切换运行级"),
    "telinit": ("system_power", "destructive", "切换运行级"),
    "systemctl": ("service_control", "privileged", "systemd 服务控制"),
    # 网络/防火墙
    "iptables": ("firewall", "privileged", "防火墙规则"),
    "ip6tables": ("firewall", "privileged", "防火墙规则"),
    "nft": ("firewall", "privileged", "防火墙规则"),
    "ufw": ("firewall", "privileged", "防火墙规则"),
    "firewall-cmd": ("firewall", "privileged", "防火墙规则"),
    # 账号
    "useradd": ("account", "privileged", "新增用户"),
    "userdel": ("account", "privileged", "删除用户"),
    "usermod": ("account", "privileged", "修改用户"),
    "groupadd": ("account", "privileged", "新增组"),
    "groupdel": ("account", "privileged", "删除组"),
    "passwd": ("account", "privileged", "修改口令"),
    "chpasswd": ("account", "privileged", "批量改口令"),
    "visudo": ("account", "privileged", "编辑 sudoers"),
    "sysctl": ("kernel_tuning", "privileged", "修改内核参数"),
    "ldconfig": ("system_libs", "privileged", "重建动态库缓存"),
    # 容器运行时（等价 root）
    "docker": ("container_runtime", "privileged", "容器运行时通常等价 root"),
    "podman": ("container_runtime", "privileged", "容器运行时通常等价 root"),
}

#: 软拒绝：默认拒绝，但 ``LCMD_DENYLIST_OVERRIDE=1`` 可整体替换这份名单。
SOFT_DENY: dict[str, tuple[str, str, str]] = {
    "rm": ("file_delete", "destructive", "递归/批量删除不可逆"),
    "rmdir": ("file_delete", "mutating", "删除目录"),
    "unlink": ("file_delete", "mutating", "删除文件"),
    "chmod": ("permission_change", "mutating", "修改权限位"),
    "chown": ("permission_change", "mutating", "修改属主"),
    "chgrp": ("permission_change", "mutating", "修改属组"),
    "setfacl": ("permission_change", "mutating", "修改 ACL"),
    "setcap": ("permission_change", "privileged", "修改 capability"),
    "kill": ("process_control", "process_control", "向进程发信号"),
    "pkill": ("process_control", "process_control", "按名杀进程"),
    "killall": ("process_control", "process_control", "批量杀进程"),
    "crontab": ("scheduler", "mutating", "修改定时任务"),
    "at": ("scheduler", "mutating", "提交定时任务"),
    "batch": ("scheduler", "mutating", "提交定时任务"),
}

#: 内置只读安全集：strict 模式默认放行这些（仍受 HARD_DENY 约束）。
BUILTIN_SAFE: frozenset[str] = frozenset(
    {
        "ls", "cat", "tac", "head", "tail", "wc", "grep", "egrep", "fgrep", "rg", "ag",
        "find", "locate", "plocate", "tree", "stat", "file", "du", "df", "lsblk", "lscpu",
        "free", "uptime", "date", "cal", "whoami", "id", "groups", "uname", "hostname",
        "pwd", "echo", "printf", "seq", "true", "false", "test", "expr",
        "basename", "dirname", "realpath", "readlink", "md5sum", "sha1sum", "sha256sum",
        "sha512sum", "cksum", "cmp", "diff", "comm", "cut", "paste", "sort", "uniq", "tr",
        "fold", "nl", "numfmt", "column", "jq", "yq", "od", "xxd", "hexdump", "strings",
        "less", "more", "which", "whereis", "type", "tty", "printenv", "ps", "pgrep",
        "pidof", "journalctl", "dmesg", "getent", "ss", "lsof", "git", "python3", "python",
    }
)

#: (risk, category) —— 仅用于“这条命令大概什么性质”，不决定放行。
RISK_TABLE: dict[str, tuple[str, str]] = {
    **{name: ("read_only", "read_only") for name in BUILTIN_SAFE},
    **{name: ("privileged", category) for name, (category, _, _) in HARD_DENY.items()},
    **{name: ("destructive" if risk == "destructive" else risk, category) for name, (category, risk, _) in SOFT_DENY.items()},
    # 写文件/构建
    "cp": ("mutating", "file_write"),
    "mv": ("mutating", "file_write"),
    "install": ("mutating", "file_write"),
    "mkdir": ("mutating", "file_write"),
    "touch": ("mutating", "file_write"),
    "ln": ("mutating", "file_write"),
    "link": ("mutating", "file_write"),
    "mktemp": ("mutating", "file_write"),
    "truncate": ("destructive", "file_write"),
    "tee": ("mutating", "file_write"),
    "sed": ("mutating", "file_write"),
    "awk": ("read_only", "read_only"),
    "rsync": ("mutating", "file_write"),
    "tar": ("mutating", "archive"),
    "gzip": ("mutating", "archive"),
    "gunzip": ("mutating", "archive"),
    "zip": ("mutating", "archive"),
    "unzip": ("mutating", "archive"),
    "7z": ("mutating", "archive"),
    "patch": ("mutating", "file_write"),
    # 代码/构建工具（可任意写文件、装依赖）
    "git": ("mutating", "vcs"),
    "hg": ("mutating", "vcs"),
    "svn": ("mutating", "vcs"),
    "pip": ("network", "package_manager"),
    "pip3": ("network", "package_manager"),
    "npm": ("network", "package_manager"),
    "pnpm": ("network", "package_manager"),
    "yarn": ("network", "package_manager"),
    "cargo": ("network", "build"),
    "make": ("mutating", "build"),
    "cmake": ("mutating", "build"),
    "gcc": ("mutating", "build"),
    "g++": ("mutating", "build"),
    "go": ("mutating", "build"),
    "rustc": ("mutating", "build"),
    "python3": ("unknown", "interpreter"),
    "python": ("unknown", "interpreter"),
    "perl": ("unknown", "interpreter"),
    "ruby": ("unknown", "interpreter"),
    "node": ("unknown", "interpreter"),
    "php": ("unknown", "interpreter"),
    # 网络
    "curl": ("network", "http"),
    "wget": ("network", "http"),
    "http": ("network", "http"),
    "https": ("network", "http"),
    "ssh": ("network", "remote_shell"),
    "scp": ("network", "file_transfer"),
    "sftp": ("network", "file_transfer"),
    "ftp": ("network", "file_transfer"),
    "telnet": ("network", "remote_shell"),
    "nc": ("network", "raw_socket"),
    "ncat": ("network", "raw_socket"),
    "netcat": ("network", "raw_socket"),
    "socat": ("network", "raw_socket"),
    "ping": ("network", "probe"),
    "ping6": ("network", "probe"),
    "traceroute": ("network", "probe"),
    "dig": ("network", "dns"),
    "host": ("network", "dns"),
    "nslookup": ("network", "dns"),
    "whois": ("network", "probe"),
    "aria2c": ("network", "http"),
    "apt": ("privileged", "package_manager"),
    "apt-get": ("privileged", "package_manager"),
    "dpkg": ("privileged", "package_manager"),
    "yum": ("privileged", "package_manager"),
    "dnf": ("privileged", "package_manager"),
    "apk": ("privileged", "package_manager"),
    "pacman": ("privileged", "package_manager"),
    "snap": ("privileged", "package_manager"),
    "kubectl": ("privileged", "orchestration"),
    "helm": ("privileged", "orchestration"),
    # 进程控制
    "nice": ("process_control", "process_control"),
    "renice": ("process_control", "process_control"),
    "ionice": ("process_control", "process_control"),
    "chrt": ("process_control", "process_control"),
    "taskset": ("process_control", "process_control"),
    "supervisorctl": ("process_control", "service_control"),
    "service": ("privileged", "service_control"),
    "launchctl": ("privileged", "service_control"),
    **{name: ("shell_wrapper", "shell_wrapper") for name in SHELL_COMMANDS | WRAPPER_COMMANDS},
}

BASE_ENV_ALLOWED: frozenset[str] = frozenset(
    {
        "PATH", "HOME", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "LC_NUMERIC",
        "LC_TIME", "LC_COLLATE", "TERM", "TZ", "USER", "LOGNAME", "TMPDIR", "SHELL",
        "COLUMNS", "LINES", "NO_COLOR", "FORCE_COLOR", "TZDIR",
    }
)

#: 注入类环境变量：无论如何都不允许由调用方设置。
ENV_DENIED: frozenset[str] = frozenset(
    {
        "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG", "LD_DEBUG_OUTPUT",
        "LD_PROFILE", "LD_ORIGIN_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
        "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT", "PYTHONEXECUTABLE",
        "BASH_ENV", "ENV", "IFS", "SHELLOPTS", "BASHOPTS", "PS4", "PROMPT_COMMAND",
        "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_ASKPASS", "SSH_ASKPASS",
        "PERL5LIB", "PERLLIB", "RUBYOPT", "RUBYLIB", "NODE_OPTIONS", "NODE_PATH",
        "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "LESSOPEN", "LESSCLOSE", "PAGER", "EDITOR",
        "VISUAL", "SSLKEYLOGFILE", "CDPATH", "GLOBIGNORE", "BROWSER", "MALLOC_CONF",
        "GLIBC_TUNABLES", "LOCPATH", "NLSPATH", "TMP", "TEMP",
    }
)

#: 即使在白名单里也不接受调用方覆盖：会改变子进程对其它命令的解析结果。
ENV_OVERRIDE_DENIED: frozenset[str] = ENV_DENIED | {"PATH"}

_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MAX_ENV_VALUE_BYTES = 8192


@dataclass(frozen=True, slots=True)
class Decision:
    """对一条命令的最终判定。"""

    allowed: bool
    risk: str
    category: str | None
    reason: str | None
    matched_rule: str | None

    def deny_reason(self, command: str) -> str:
        return self.reason or f"命令 {command} 被策略拒绝"


class PolicyEngine:
    """把 :class:`Settings` 变成可执行的判定逻辑。"""

    def __init__(self, settings: Settings, command_dirs: Sequence[str] = ()) -> None:
        self.settings = settings
        self.command_dirs = tuple(command_dirs)
        if settings.policy_mode == "unrestricted":
            # 完全放开：内置硬/软拒绝都不生效，只保留运维显式写的 LCMD_DENYLIST。
            self._soft: dict[str, tuple[str, str, str]] = {}
        elif settings.denylist_override:
            self._soft: dict[str, tuple[str, str, str]] = {
                name: ("operator_deny", RISK_TABLE.get(name, ("unknown", "operator_deny"))[0], "由 LCMD_DENYLIST 指定")
                for name in settings.denylist
            }
        else:
            self._soft = dict(SOFT_DENY)
            # shell 包装器默认拒绝：它们会绕过“命令与参数分离”的契约，
            # 等价于给调用方一个 shell。需要时用 LCMD_DENYLIST_OVERRIDE 或
            # permissive 模式显式放开。
            for wrapper in SHELL_COMMANDS | WRAPPER_COMMANDS:
                self._soft.setdefault(
                    wrapper,
                    ("shell_wrapper", "shell_wrapper", "shell/包装器会绕过 argv 分离，默认拒绝"),
                )
        self._operator_deny = frozenset(settings.denylist)

    # ------------------------------------------------------------------ 查询
    @property
    def hard_deny_names(self) -> frozenset[str]:
        return frozenset(HARD_DENY)

    @property
    def effective_denylist(self) -> frozenset[str]:
        if self.settings.policy_mode == "unrestricted":
            return frozenset(self._operator_deny)
        names = set(self._soft)
        names |= set(self._operator_deny)
        return frozenset(names - set(HARD_DENY))

    def risk_of(self, name: str) -> tuple[str, str | None]:
        if name in HARD_DENY:
            category, risk, _ = HARD_DENY[name]
            return risk, category
        if name in SOFT_DENY:
            category, risk, _ = SOFT_DENY[name]
            return risk, category
        entry = RISK_TABLE.get(name)
        if entry:
            return entry[0], entry[1]
        return "unknown", None

    # ------------------------------------------------------------------ 判定
    def evaluate(
        self,
        name: str,
        path: str | None = None,
        *,
        allowed_dirs: Sequence[str] = (),
    ) -> Decision:
        """判定 ``name``（可选 ``path``）能否执行。

        ``allowed_dirs`` 用于绝对路径查询的目录白名单；为空则不做目录限制。
        """
        risk, category = self.risk_of(name)
        mode = self.settings.policy_mode

        if mode != "unrestricted" and name in HARD_DENY:
            detail = HARD_DENY[name][2]
            return Decision(False, risk, "hard_deny", f"{name} 属于硬拒绝命令（{detail}），任何模式都不允许执行。", f"hard_deny:{name}")

        if mode != "unrestricted" and path is not None and allowed_dirs:
            from .paths import match_root  # 局部导入避免循环

            if match_root(path, allowed_dirs) is None:
                return Decision(
                    False,
                    risk,
                    "path_forbidden",
                    f"可执行文件 {path} 不在允许的命令目录内，拒绝执行。",
                    "path_not_allowed",
                )

        if name in self._operator_deny:
            return Decision(False, risk, "operator_deny", f"{name} 被 LCMD_DENYLIST 显式拒绝。", f"operator_deny:{name}")

        if mode == "unrestricted":
            return Decision(True, risk, category, None, "unrestricted")

        if mode == "permissive":
            return Decision(True, risk, category, None, None)

        if mode == "strict":
            if name in self.settings.allowlist:
                return Decision(True, risk, category, None, f"allowlist:{name}")
            if name in BUILTIN_SAFE and name not in self._soft:
                return Decision(True, risk, category, None, f"builtin_safe:{name}")
            return Decision(
                False,
                risk,
                "strict_not_allowlisted",
                f"strict 模式只放行内置只读安全集与 LCMD_ALLOWLIST，{name} 不在其中。",
                "strict_not_allowlisted",
            )

        # standard
        if name in self._soft:
            category, risk, detail = self._soft[name]
            rule = f"soft_deny:{name}" if not self.settings.denylist_override else f"operator_deny:{name}"
            return Decision(False, risk, category, f"{name} 默认拒绝（{detail}）；需要时由运维调整 LCMD_DENYLIST。", rule)

        return Decision(True, risk, category, None, f"default_allow:{name}")

    # ------------------------------------------------------------------ 环境
    def build_env(self, base_environ: Mapping[str, str], overrides: Mapping[str, str] | None) -> dict[str, str]:
        """构造子进程环境：只透传白名单基础键 + 调用方显式覆盖。"""
        env: dict[str, str] = {}
        for key in BASE_ENV_ALLOWED:
            value = base_environ.get(key)
            if value is not None:
                env[key] = value
        # PATH 始终以当前生效的 PATH 为准（LCMD_PATH 优先）
        env["PATH"] = self.settings.effective_path_env() or base_environ.get("PATH", os.defpath)

        if overrides and self.settings.policy_mode == "unrestricted":
            # 完整控制档位：调用方可设置任意合法键（含 LD_PRELOAD / PATH），
            # 只保留“名字合法 + 值是字符串 + 无 NUL + 大小/数量上限”的硬校验。
            if len(overrides) > self.settings.max_env_keys:
                fail(
                    ErrorCode.LIMIT_EXCEEDED,
                    f"env 键数量 {len(overrides)} 超过上限 {self.settings.max_env_keys}。",
                    "减少覆盖的环境变量；批量环境应由运维通过服务启动环境提供。",
                    {"limit": "env_keys", "value": len(overrides), "maximum": self.settings.max_env_keys},
                )
            for key, value in overrides.items():
                self._validate_env_pair(key, value)
                env[key] = value
            return env

        if overrides:
            if len(overrides) > self.settings.max_env_keys:
                fail(
                    ErrorCode.LIMIT_EXCEEDED,
                    f"env 键数量 {len(overrides)} 超过上限 {self.settings.max_env_keys}。",
                    "减少覆盖的环境变量；批量环境应由运维通过服务启动环境提供。",
                    {"limit": "env_keys", "value": len(overrides), "maximum": self.settings.max_env_keys},
                )
            allowed = self.allowed_env_keys
            for key, value in overrides.items():
                if not _ENV_KEY_RE.match(key):
                    fail(
                        ErrorCode.ENV_KEY_FORBIDDEN,
                        f"环境变量名非法：{key!r}",
                        "环境变量名需匹配 ^[A-Za-z_][A-Za-z0-9_]*$。",
                        {"key": key},
                    )
                if key in ENV_OVERRIDE_DENIED:
                    fail(
                        ErrorCode.ENV_KEY_FORBIDDEN,
                        f"环境变量 {key} 被策略禁止设置（可影响动态链接/解释器/子进程解析）。",
                        f"移除该键；允许覆盖的键：{sorted(allowed)}",
                        {"key": key, "denied": sorted(ENV_OVERRIDE_DENIED)},
                    )
                if key not in allowed:
                    fail(
                        ErrorCode.ENV_KEY_FORBIDDEN,
                        f"环境变量 {key} 不在白名单内。",
                        f"可用 LCMD_ENV_ALLOWLIST_EXTRA 显式放行；当前允许：{sorted(allowed)}",
                        {"key": key, "allowed": sorted(allowed)},
                    )
                if not isinstance(value, str):
                    fail(ErrorCode.ENV_VALUE_INVALID, f"环境变量 {key} 的值必须是字符串。", "把所有 env 值写成字符串。", {"key": key})
                if "\x00" in value:
                    fail(ErrorCode.ENV_VALUE_INVALID, f"环境变量 {key} 的值包含 NUL 字节。", "移除 NUL 字节。", {"key": key})
                if len(value.encode("utf-8", "replace")) > _MAX_ENV_VALUE_BYTES:
                    fail(
                        ErrorCode.ENV_VALUE_INVALID,
                        f"环境变量 {key} 的值超过 {_MAX_ENV_VALUE_BYTES} 字节。",
                        "缩短取值；大块内容请通过文件或 stdin 传递。",
                        {"key": key},
                    )
                env[key] = value
        return env

    def _validate_env_pair(self, key: str, value: object) -> None:
        """键名/值的基础校验（与模式无关，任何档位都要过）。"""
        if not _ENV_KEY_RE.match(key):
            fail(
                ErrorCode.ENV_KEY_FORBIDDEN,
                f"环境变量名非法：{key!r}",
                "环境变量名需匹配 ^[A-Za-z_][A-Za-z0-9_]*$。",
                {"key": key},
            )
        if not isinstance(value, str):
            fail(ErrorCode.ENV_VALUE_INVALID, f"环境变量 {key} 的值必须是字符串。", "把所有 env 值写成字符串。", {"key": key})
        if "\x00" in value:
            fail(ErrorCode.ENV_VALUE_INVALID, f"环境变量 {key} 的值包含 NUL 字节。", "移除 NUL 字节。", {"key": key})
        if len(value.encode("utf-8", "replace")) > _MAX_ENV_VALUE_BYTES:
            fail(
                ErrorCode.ENV_VALUE_INVALID,
                f"环境变量 {key} 的值超过 {_MAX_ENV_VALUE_BYTES} 字节。",
                "缩短取值；大块内容请通过文件或 stdin 传递。",
                {"key": key},
            )

    @property
    def allowed_env_keys(self) -> frozenset[str]:
        return frozenset((BASE_ENV_ALLOWED - {"PATH"}) | set(self.settings.env_allowlist_extra))

    # ------------------------------------------------------------------ 参数
    def check_args(self, args: Sequence[str]) -> None:
        if len(args) > self.settings.max_args:
            fail(
                ErrorCode.LIMIT_EXCEEDED,
                f"参数个数 {len(args)} 超过上限 {self.settings.max_args}。",
                "减少参数，或改用批处理脚本（脚本内自行限流）。",
                {"limit": "args", "value": len(args), "maximum": self.settings.max_args},
            )
        total = 0
        for index, arg in enumerate(args):
            if not isinstance(arg, str):
                fail(ErrorCode.INVALID_ARGUMENT, f"args[{index}] 不是字符串。", "args 必须是字符串数组。", {"index": index})
            if "\x00" in arg:
                fail(ErrorCode.INVALID_ARGUMENT, f"args[{index}] 含 NUL 字节。", "移除 NUL 字节。", {"index": index})
            if len(arg) > self.settings.max_arg_length:
                fail(
                    ErrorCode.LIMIT_EXCEEDED,
                    f"args[{index}] 长度 {len(arg)} 超过上限 {self.settings.max_arg_length} 字符。",
                    "把长文本写入文件后用参数引用文件路径。",
                    {"limit": "arg_length", "index": index},
                )
            total += len(arg.encode("utf-8", "replace"))
        if total > 128 * 1024:
            fail(
                ErrorCode.LIMIT_EXCEEDED,
                f"argv 总长度 {total} 字节超过上限 {128 * 1024} 字节。",
                "拆分任务；大量输入请走文件或 stdin。",
                {"limit": "argv_total_bytes", "value": total},
            )

    def resolve_timeout(self, timeout_seconds: float | None) -> float:
        if timeout_seconds is None:
            return self.settings.default_timeout_seconds
        if timeout_seconds > self.settings.max_timeout_seconds:
            fail(
                ErrorCode.LIMIT_EXCEEDED,
                f"timeout_seconds={timeout_seconds} 超过服务端上限 {self.settings.max_timeout_seconds}。",
                f"把 timeout_seconds 降到 <= {self.settings.max_timeout_seconds}，或调整 LCMD_MAX_TIMEOUT_SECONDS。",
                {"limit": "timeout_seconds", "value": timeout_seconds, "maximum": self.settings.max_timeout_seconds},
            )
        if timeout_seconds <= 0:
            fail(ErrorCode.INVALID_ARGUMENT, f"timeout_seconds 必须 > 0，收到 {timeout_seconds}。", "使用正数秒。", {})
        return timeout_seconds

    def resolve_output_limit(self, max_output_bytes: int | None) -> int:
        if max_output_bytes is None:
            return self.settings.max_output_bytes
        if max_output_bytes > self.settings.max_output_bytes:
            fail(
                ErrorCode.LIMIT_EXCEEDED,
                f"max_output_bytes={max_output_bytes} 超过服务端上限 {self.settings.max_output_bytes}。",
                "改用更精确的过滤（grep/head），或由运维提高 LCMD_MAX_OUTPUT_BYTES。",
                {"limit": "max_output_bytes", "value": max_output_bytes, "maximum": self.settings.max_output_bytes},
            )
        if max_output_bytes <= 0:
            fail(ErrorCode.INVALID_ARGUMENT, f"max_output_bytes 必须 > 0，收到 {max_output_bytes}。", "使用正整数。", {})
        return max_output_bytes

    def check_stdin(self, stdin: str | None) -> None:
        if stdin is None:
            return
        if not self.settings.allow_stdin:
            fail(
                ErrorCode.POLICY_DENIED,
                "服务端通过 LCMD_ALLOW_STDIN=0 关闭了 stdin 注入。",
                "改用参数或临时文件传递输入。",
                {"policy": "allow_stdin"},
            )
        if "\x00" in stdin:
            # NUL 在文本 stdin 里无意义且可能干扰下游解析
            fail(ErrorCode.INVALID_ARGUMENT, "stdin 含 NUL 字节。", "移除 NUL 字节后重试。", {})
        size = len(stdin.encode("utf-8", "replace"))
        if size > self.settings.max_stdin_bytes:
            fail(
                ErrorCode.LIMIT_EXCEEDED,
                f"stdin 大小 {size} 字节超过上限 {self.settings.max_stdin_bytes}。",
                "把大输入写入文件后用参数引用。",
                {"limit": "stdin_bytes", "value": size, "maximum": self.settings.max_stdin_bytes},
            )
