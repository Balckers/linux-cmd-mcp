"""配置加载与校验。

所有可调项都来自环境变量，启动时一次性读取并校验；缺项/非法值直接
以 :class:`ConfigError` 终止进程，而不是在运行时静默降级。

变量一览（完整说明见 docs/POLICY.md）：

===============================  ==============================  ================
变量                             含义                             默认
===============================  ==============================  ================
LCMD_POLICY_MODE                 策略档位                            unrestricted
LCMD_ALLOWLIST                   额外放行命令（逗号/分号分隔）       空
LCMD_DENYLIST                    额外拒绝命令（逗号/分号分隔）       空
LCMD_DENYLIST_OVERRIDE           置 1 时用 LCMD_DENYLIST 替换内置软名单  false
LCMD_ALLOWED_WORKDIRS            允许作为 cwd 的根目录               空（不限制）
LCMD_COMMAND_DIRS                额外允许绝对路径执行的目录           空
LCMD_PATH                        覆盖用于命令发现的 PATH            进程 PATH
LCMD_MAX_TIMEOUT_SECONDS         单次执行超时上限                    60
LCMD_DEFAULT_TIMEOUT_SECONDS     未显式传入时的超时                  20
LCMD_MAX_OUTPUT_BYTES            stdout/stderr 各自保留字节上限       1048576
LCMD_MAX_STDIN_BYTES             允许写入的 stdin 字节上限            1048576
LCMD_MAX_ARGS                    argv 元素上限                       256
LCMD_MAX_ARG_LENGTH              单个 argv 元素字符上限               4096
LCMD_MAX_ENV_KEYS                额外环境变量键上限                   32
LCMD_MAX_CONCURRENCY             并发执行上限                        4
LCMD_DISCOVERY_TTL_SECONDS       命令发现缓存 TTL                    5
LCMD_ALLOW_STDIN                 是否允许传 stdin                     true
LCMD_ENV_ALLOWLIST_EXTRA         额外允许透传的环境变量键             空
LCMD_LOG_LEVEL                   日志级别（只写 stderr）              WARNING
LCMD_INCLUDE_DEFAULT_DIRS        并入标准命令目录一起扫描             true
LCMD_AUTH_TOKEN                 HTTP/SSE Bearer 令牌（≥16 字符）    空
LCMD_HTTP_HOST                  SSE/HTTP 监听地址                  127.0.0.1
LCMD_HTTP_PORT                  SSE/HTTP 监听端口                  8765
LCMD_ALLOWED_ORIGINS            额外允许的 Origin                  空
===============================  ==============================  ================
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace

from .errors import ConfigError

HARD_MAX_TIMEOUT_SECONDS = 3600.0
HARD_MAX_OUTPUT_BYTES = 32 * 1024 * 1024
HARD_MAX_STDIN_BYTES = 4 * 1024 * 1024
HARD_MAX_ARGS = 1024
HARD_MAX_ARG_LENGTH = 64 * 1024
HARD_MAX_ENV_KEYS = 256
HARD_MAX_CONCURRENCY = 32

POLICY_MODES = ("strict", "standard", "permissive", "unrestricted")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

_SEPARATORS = re.compile(r"[,;\s]+")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True, slots=True)
class Settings:
    """不可变的运行期配置快照。"""

    policy_mode: str
    allowlist: tuple[str, ...]
    denylist: tuple[str, ...]
    denylist_override: bool
    allowed_workdirs: tuple[str, ...]
    command_dirs: tuple[str, ...]
    path_env: str | None
    max_timeout_seconds: float
    default_timeout_seconds: float
    max_output_bytes: int
    max_stdin_bytes: int
    max_args: int
    max_arg_length: int
    max_env_keys: int
    max_concurrency: int
    discovery_ttl_seconds: float
    allow_stdin: bool
    env_allowlist_extra: tuple[str, ...]
    log_level: str
    include_default_dirs: bool
    auth_token: str | None
    http_host: str
    http_port: int
    allowed_origins: tuple[str, ...]

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        env = os.environ if environ is None else environ

        mode = _read(env, "LCMD_POLICY_MODE", "unrestricted").lower()
        if mode not in POLICY_MODES:
            raise ConfigError(
                f"LCMD_POLICY_MODE={mode!r} 非法",
                "可选值：unrestricted（默认，SSH 级完整控制）/ permissive / standard / strict",
            )

        log_level = _read(env, "LCMD_LOG_LEVEL", "WARNING").upper()
        if log_level not in LOG_LEVELS:
            raise ConfigError(
                f"LCMD_LOG_LEVEL={log_level!r} 非法",
                "可选值：DEBUG / INFO / WARNING / ERROR / CRITICAL",
            )

        max_timeout = _read_float(env, "LCMD_MAX_TIMEOUT_SECONDS", 60.0)
        _require_range("LCMD_MAX_TIMEOUT_SECONDS", max_timeout, 0.1, HARD_MAX_TIMEOUT_SECONDS)

        default_timeout = _read_float(env, "LCMD_DEFAULT_TIMEOUT_SECONDS", 20.0)
        explicit_default_timeout = "LCMD_DEFAULT_TIMEOUT_SECONDS" in env
        if default_timeout > max_timeout:
            if explicit_default_timeout:
                raise ConfigError(
                    f"LCMD_DEFAULT_TIMEOUT_SECONDS={default_timeout:g} 大于 LCMD_MAX_TIMEOUT_SECONDS={max_timeout:g}",
                    "默认超时不能高于上限：把 LCMD_DEFAULT_TIMEOUT_SECONDS 调小，或把 LCMD_MAX_TIMEOUT_SECONDS 调大。",
                )
            # 运维只收紧了天花板（max），未显式设置默认值：默认值随之夹到上限，
            # 否则一条完全合理的 LCMD_MAX_TIMEOUT_SECONDS=10 会让服务器起不来。
            default_timeout = max_timeout
        _require_range("LCMD_DEFAULT_TIMEOUT_SECONDS", default_timeout, 0.1, max_timeout)

        max_output = _read_int(env, "LCMD_MAX_OUTPUT_BYTES", 1024 * 1024)
        _require_range("LCMD_MAX_OUTPUT_BYTES", max_output, 1024, HARD_MAX_OUTPUT_BYTES)

        max_stdin = _read_int(env, "LCMD_MAX_STDIN_BYTES", 1024 * 1024)
        _require_range("LCMD_MAX_STDIN_BYTES", max_stdin, 0, HARD_MAX_STDIN_BYTES)

        max_args = _read_int(env, "LCMD_MAX_ARGS", 256)
        _require_range("LCMD_MAX_ARGS", max_args, 1, HARD_MAX_ARGS)

        max_arg_length = _read_int(env, "LCMD_MAX_ARG_LENGTH", 4096)
        _require_range("LCMD_MAX_ARG_LENGTH", max_arg_length, 1, HARD_MAX_ARG_LENGTH)

        max_env_keys = _read_int(env, "LCMD_MAX_ENV_KEYS", 32)
        _require_range("LCMD_MAX_ENV_KEYS", max_env_keys, 0, HARD_MAX_ENV_KEYS)

        max_concurrency = _read_int(env, "LCMD_MAX_CONCURRENCY", 4)
        _require_range("LCMD_MAX_CONCURRENCY", max_concurrency, 1, HARD_MAX_CONCURRENCY)

        discovery_ttl = _read_float(env, "LCMD_DISCOVERY_TTL_SECONDS", 5.0)
        _require_range("LCMD_DISCOVERY_TTL_SECONDS", discovery_ttl, 0.0, 300.0)

        allowlist = _names(_read_list(env, "LCMD_ALLOWLIST"), "LCMD_ALLOWLIST")
        denylist = _names(_read_list(env, "LCMD_DENYLIST"), "LCMD_DENYLIST")
        allowed_workdirs = _absolute_dirs(_read_list(env, "LCMD_ALLOWED_WORKDIRS"), "LCMD_ALLOWED_WORKDIRS")
        command_dirs = _absolute_dirs(_read_list(env, "LCMD_COMMAND_DIRS"), "LCMD_COMMAND_DIRS")
        env_allow_extra = _env_names(_read_list(env, "LCMD_ENV_ALLOWLIST_EXTRA"), "LCMD_ENV_ALLOWLIST_EXTRA")

        http_port = _read_int(env, "LCMD_HTTP_PORT", 8765)
        _require_range("LCMD_HTTP_PORT", http_port, 1, 65535)
        http_host = _read(env, "LCMD_HTTP_HOST", "127.0.0.1")
        if not http_host or any(ch.isspace() for ch in http_host):
            raise ConfigError(f"LCMD_HTTP_HOST={http_host!r} 非法", "写主机名或 IP，例如 127.0.0.1、0.0.0.0")
        token_raw = env.get("LCMD_AUTH_TOKEN")
        auth_token = token_raw.strip() if token_raw else None
        if auth_token is not None:
            if len(auth_token) < 16:
                raise ConfigError(
                    "LCMD_AUTH_TOKEN 太短（至少 16 个字符）",
                    "用 openssl rand -hex 32 生成；弱令牌等于没有鉴权。",
                )
            if "\x00" in auth_token or any(ch.isspace() for ch in auth_token):
                raise ConfigError(
                    "LCMD_AUTH_TOKEN 含空白或 NUL",
                    "令牌必须是单个不含空白的字符串。",
                )
        allowed_origins = _read_list(env, "LCMD_ALLOWED_ORIGINS")

        # LCMD_PATH 只要被显式设置（包括空字符串）就覆盖进程 PATH：
        # 空值表示“不搜索任何 PATH 目录”，而不是“回退到进程 PATH”。
        path_env = env["LCMD_PATH"] if "LCMD_PATH" in env else None

        settings = cls(
            policy_mode=mode,
            allowlist=allowlist,
            denylist=denylist,
            denylist_override=_read_bool(env, "LCMD_DENYLIST_OVERRIDE", False),
            allowed_workdirs=allowed_workdirs,
            command_dirs=command_dirs,
            path_env=path_env,
            max_timeout_seconds=max_timeout,
            default_timeout_seconds=default_timeout,
            max_output_bytes=max_output,
            max_stdin_bytes=max_stdin,
            max_args=max_args,
            max_arg_length=max_arg_length,
            max_env_keys=max_env_keys,
            max_concurrency=max_concurrency,
            discovery_ttl_seconds=discovery_ttl,
            allow_stdin=_read_bool(env, "LCMD_ALLOW_STDIN", True),
            env_allowlist_extra=env_allow_extra,
            log_level=log_level,
            include_default_dirs=_read_bool(env, "LCMD_INCLUDE_DEFAULT_DIRS", True),
            auth_token=auth_token,
            http_host=http_host,
            http_port=http_port,
            allowed_origins=allowed_origins,
        )

        # 交叉校验：默认超时不得超过上限（已单独校验），allowlist 与 denylist 不得冲突。
        overlap = set(settings.allowlist) & set(settings.denylist)
        if overlap:
            raise ConfigError(
                f"命令同时出现在 LCMD_ALLOWLIST 与 LCMD_DENYLIST：{sorted(overlap)}",
                "拒绝优先；请从其中一处移除，避免语义不清。",
            )
        return settings

    def with_changes(self, **changes: object) -> "Settings":
        """测试/嵌入场景下的派生配置（保持不可变语义）。"""
        return replace(self, **changes)  # type: ignore[arg-type]

    @property
    def is_loopback_bind(self) -> bool:
        return self.http_host in {"127.0.0.1", "localhost", "::1"}

    @property
    def auth_required(self) -> bool:
        """监听非回环地址时必须有令牌；回环地址有令牌则按令牌校验。"""
        return self.auth_token is not None

    def http_summary(self) -> dict[str, object]:
        """HTTP/SSE 传输摘要（不回显令牌值）。"""
        return {
            "host": self.http_host,
            "port": self.http_port,
            "auth_enabled": self.auth_token is not None,
            "origin_check": True,
            "allowed_origins": list(self.allowed_origins) or ["loopback(http://127.0.0.1, http://localhost)"],
        }

    def effective_path_env(self) -> str:
        """命令发现实际使用的 PATH。"""
        if self.path_env is not None:
            return self.path_env
        return os.environ.get("PATH", "")

    def policy_summary(self) -> dict[str, object]:
        return {
            "mode": self.policy_mode,
            "allowlist": list(self.allowlist),
            "denylist_extra": list(self.denylist),
            "denylist_override": self.denylist_override,
            "allowed_workdirs": list(self.allowed_workdirs),
            "command_dirs": list(self.command_dirs),
            "max_timeout_seconds": self.max_timeout_seconds,
            "default_timeout_seconds": self.default_timeout_seconds,
            "max_output_bytes": self.max_output_bytes,
            "max_stdin_bytes": self.max_stdin_bytes,
            "max_args": self.max_args,
            "max_arg_length": self.max_arg_length,
            "max_env_keys": self.max_env_keys,
            "max_concurrency": self.max_concurrency,
            "allow_stdin": self.allow_stdin,
            "include_default_dirs": self.include_default_dirs,
        }


def _read(env: Mapping[str, str], key: str, default: str) -> str:
    raw = env.get(key)
    if raw is None:
        return default
    value = raw.strip()
    return value or default


def _read_int(env: Mapping[str, str], key: str, default: int) -> int:
    raw = env.get(key)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip(), 10)
    except ValueError:
        raise ConfigError(f"{key}={raw!r} 不是整数", "请填写十进制整数，例如 1048576") from None


def _read_float(env: Mapping[str, str], key: str, default: float) -> float:
    raw = env.get(key)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw.strip())
    except ValueError:
        raise ConfigError(f"{key}={raw!r} 不是数字", "请填写数字，例如 30 或 0.5") from None


def _read_bool(env: Mapping[str, str], key: str, default: bool) -> bool:
    raw = env.get(key)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{key}={raw!r} 不是布尔值", "可用 1/0、true/false、yes/no、on/off")


def _read_list(env: Mapping[str, str], key: str) -> tuple[str, ...]:
    raw = env.get(key)
    if raw is None:
        return ()
    return tuple(item for item in _SEPARATORS.split(raw.strip()) if item)


def _names(items: Sequence[str], source: str) -> tuple[str, ...]:
    result: list[str] = []
    for item in items:
        if "/" in item or item in {".", ".."}:
            raise ConfigError(
                f"{source} 中的条目 {item!r} 不是命令名",
                "只写命令名（如 git、python3），不要写路径；路径限制由 LCMD_COMMAND_DIRS 负责。",
            )
        if item not in result:
            result.append(item)
    return tuple(result)


def _absolute_dirs(items: Sequence[str], source: str) -> tuple[str, ...]:
    result: list[str] = []
    for item in items:
        expanded = os.path.expanduser(item.strip())
        if not os.path.isabs(expanded):
            raise ConfigError(
                f"{source} 中的条目 {item!r} 不是绝对路径",
                "请使用绝对路径，例如 /home/agent/work 或 /tmp；相对路径会随进程 cwd 漂移。",
            )
        normalized = os.path.normpath(expanded)
        real = os.path.realpath(normalized)
        if real not in result:
            result.append(real)
    return tuple(result)


def _env_names(items: Sequence[str], source: str) -> tuple[str, ...]:
    result: list[str] = []
    for item in items:
        if not _ENV_NAME.match(item):
            raise ConfigError(
                f"{source} 中的条目 {item!r} 不是合法环境变量名",
                "环境变量名需匹配 ^[A-Za-z_][A-Za-z0-9_]*$",
            )
        if item not in result:
            result.append(item)
    return tuple(result)


def _require_range(key: str, value: float, minimum: float, maximum: float) -> None:
    if value < minimum or value > maximum:
        raise ConfigError(
            f"{key}={value} 超出允许范围 [{minimum}, {maximum}]",
            "请调整到范围内；硬上限与下限是代码常量，不随环境变量放宽。",
        )
