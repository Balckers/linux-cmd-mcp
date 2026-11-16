"""运行期共享状态（进程内单例，由 lifespan 构造）。"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field

from .config import Settings
from .discovery import DEFAULT_COMMAND_DIRS, CommandDiscovery
from .policy import PolicyEngine


@dataclass(slots=True)
class AppState:
    """一次服务器生命周期内共享的依赖。"""

    settings: Settings
    discovery: CommandDiscovery
    policy: PolicyEngine
    semaphore: asyncio.Semaphore
    allowed_command_dirs: tuple[str, ...] = ()
    created_at: float = field(default_factory=time.monotonic)

    def summary(self) -> dict[str, object]:
        return self.settings.policy_summary()


def _safe_cwd() -> str:
    try:
        cwd = os.getcwd()
    except OSError:
        return "/"
    return cwd if os.path.isdir(cwd) else "/"


def build_state(settings: Settings) -> AppState:
    extra_dirs: tuple[str, ...] = tuple(settings.command_dirs)
    if settings.include_default_dirs:
        extra_dirs = extra_dirs + tuple(d for d in DEFAULT_COMMAND_DIRS if d not in extra_dirs)
    discovery = CommandDiscovery(
        path_provider=settings.effective_path_env,
        extra_dirs=extra_dirs,
        base_cwd=_safe_cwd(),
        ttl_seconds=settings.discovery_ttl_seconds,
    )
    snapshot = discovery.snapshot(refresh=True)
    scanned = {scan_dir.path for scan_dir in snapshot.dirs if scan_dir.status == "scanned"}
    allowed_dirs = tuple(sorted(scanned)) + tuple(d for d in extra_dirs if d not in scanned)
    return AppState(
        settings=settings,
        discovery=discovery,
        policy=PolicyEngine(settings, command_dirs=allowed_dirs),
        semaphore=asyncio.Semaphore(settings.max_concurrency),
        allowed_command_dirs=allowed_dirs,
    )
