"""系统信息采集：只返回非敏感基础信息。

原则：
* 单一信息源缺失不影响整体结果，缺失项置 null 并记入 ``degraded``。
* 不依赖 GNU coreutils 的特定输出格式，优先 ``/etc/os-release``、``os.uname``、
  ``platform``、``/proc/meminfo``、``os.sysconf`` 等通用机制。
* 绝不返回密码、令牌、完整环境变量、进程列表等敏感数据。
"""

from __future__ import annotations

import os
import platform
import pwd
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

from .models import (
    CpuInfo,
    DistributionInfo,
    KernelInfo,
    MemoryInfo,
    PolicySummary,
    SystemInfoOutput,
    UserInfo,
)

_OS_RELEASE_PATHS = ("/etc/os-release", "/usr/lib/os-release")


def collect_kernel() -> KernelInfo:
    try:
        info = os.uname()
    except (AttributeError, OSError) as exc:  # 非 Linux 或受限环境
        return KernelInfo(source="os.uname", error=f"{exc.__class__.__name__}: {exc}")
    return KernelInfo(
        sysname=info.sysname,
        release=info.release,
        version=info.version,
        machine=info.machine,
        source="os.uname",
    )


def collect_distribution() -> DistributionInfo:
    """优先 platform.freedesktop_os_release()，失败再手工解析 os-release。"""
    try:
        data = platform.freedesktop_os_release()
        if data:
            return DistributionInfo(
                id=data.get("ID"),
                id_like=_split_id_like(data.get("ID_LIKE")),
                name=data.get("NAME"),
                pretty_name=data.get("PRETTY_NAME"),
                version=data.get("VERSION"),
                version_id=data.get("VERSION_ID"),
                source="platform.freedesktop_os_release",
            )
    except (OSError, RuntimeError, AttributeError) as exc:
        platform_error = f"{exc.__class__.__name__}: {exc}"
    else:  # pragma: no cover - 只在返回空 dict 时触发
        platform_error = "os-release 为空"

    for candidate in _OS_RELEASE_PATHS:
        parsed = _parse_os_release(candidate)
        if parsed is not None:
            messages = [platform_error] if platform_error else []
            return DistributionInfo(
                id=parsed.get("ID"),
                id_like=_split_id_like(parsed.get("ID_LIKE")),
                name=parsed.get("NAME"),
                pretty_name=parsed.get("PRETTY_NAME"),
                version=parsed.get("VERSION"),
                version_id=parsed.get("VERSION_ID"),
                source=f"manual:{candidate}",
                error="; ".join(messages) or None,
            )

    return DistributionInfo(source="none", error="未找到可读的 /etc/os-release 或 /usr/lib/os-release")


def _parse_os_release(path: str) -> dict[str, str] | None:
    file = Path(path)
    try:
        text = file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    result: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if key:
            result[key] = value
    return result or None


def _split_id_like(value: str | None) -> list[str]:
    if not value:
        return []
    return [item for item in value.split() if item]


def collect_cpu() -> CpuInfo:
    logical: int | None
    try:
        logical = os.cpu_count()
    except NotImplementedError:  # pragma: no cover
        logical = None
    affinity: int | None = None
    has_getaffinity = hasattr(os, "sched_getaffinity")
    if has_getaffinity:
        try:
            affinity = len(os.sched_getaffinity(0))
        except OSError:
            affinity = None
    source = "os.cpu_count"
    if has_getaffinity:
        source += " + os.sched_getaffinity"
    return CpuInfo(logical_cores=logical, affinity_cores=affinity, source=source)


def collect_memory() -> MemoryInfo:
    values = _read_meminfo()
    if values is not None:
        return MemoryInfo(
            total_bytes=values.get("MemTotal"),
            available_bytes=values.get("MemAvailable"),
            free_bytes=values.get("MemFree"),
            swap_total_bytes=values.get("SwapTotal"),
            source="/proc/meminfo",
        )

    # 回退：只拿得到物理内存总量
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        pages = os.sysconf("SC_PHYS_PAGES")
        total = int(page_size) * int(pages)
    except (ValueError, OSError, AttributeError):
        return MemoryInfo(source="none", error="/proc/meminfo 不可读，且 os.sysconf 不可用")
    return MemoryInfo(total_bytes=total, source="os.sysconf", error="/proc/meminfo 不可读，可用内存未知")


def _read_meminfo() -> dict[str, int] | None:
    try:
        with open("/proc/meminfo", encoding="utf-8", errors="replace") as handle:
            raw_lines = handle.readlines()
    except OSError:
        return None

    result: dict[str, int] = {}
    for line in raw_lines:
        key, sep, rest = line.partition(":")
        if not sep:
            continue
        tokens = rest.split()
        if not tokens:
            continue
        try:
            amount = int(tokens[0])
        except ValueError:
            continue
        if len(tokens) > 1 and tokens[1].lower() == "kb":
            amount *= 1024
        result[key.strip()] = amount
    return result or None


def collect_user() -> UserInfo:
    uid = os.geteuid() if hasattr(os, "geteuid") else None
    gid = os.getegid() if hasattr(os, "getegid") else None
    name: str | None = None
    error: str | None = None
    source = "pwd.getpwuid"
    if uid is not None:
        try:
            name = pwd.getpwuid(uid).pw_name
        except (KeyError, OSError) as exc:
            error = f"pwd.getpwuid({uid}) 失败：{exc.__class__.__name__}"
    if name is None:
        try:
            name = os.getlogin()
            source = "os.getlogin"
        except OSError:
            name = None
    return UserInfo(name=name, uid=uid, gid=gid, source=source, error=error)


def collect_hostname() -> tuple[str | None, str]:
    try:
        return socket.gethostname() or None, "socket.gethostname"
    except OSError:
        try:
            return os.uname().nodename, "os.uname"
        except (AttributeError, OSError):
            return None, "none"


def collect_system_info(policy_summary: dict[str, object]) -> SystemInfoOutput:
    degraded: list[str] = []

    kernel = collect_kernel()
    if kernel.error:
        degraded.append("kernel")

    distribution = collect_distribution()
    if distribution.error and distribution.id is None:
        degraded.append("distribution")

    hostname, hostname_source = collect_hostname()
    if hostname is None:
        degraded.append("hostname")

    cpu = collect_cpu()
    if cpu.logical_cores is None:
        degraded.append("cpu")

    memory = collect_memory()
    if memory.total_bytes is None:
        degraded.append("memory")

    user = collect_user()
    if user.name is None:
        degraded.append("current_user")

    try:
        architecture = platform.machine() or kernel.machine
    except Exception:  # noqa: BLE001 - platform 在极端环境下可能抛异常
        architecture = kernel.machine

    return SystemInfoOutput(
        kernel=kernel,
        distribution=distribution,
        architecture=architecture,
        hostname=hostname,
        hostname_source=hostname_source,
        cpu=cpu,
        memory=memory,
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        python_implementation=platform.python_implementation(),
        current_user=user,
        degraded=degraded,
        collected_at=datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        policy=PolicySummary(**policy_summary),  # type: ignore[arg-type]
    )
