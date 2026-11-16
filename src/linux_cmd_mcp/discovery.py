"""命令发现：从进程 PATH 动态扫描可执行文件。

设计要点
--------
* 只依赖 ``PATH`` + ``os.scandir``，不假设 ``/bin``、``/usr/bin`` 是唯一来源。
* 相对、空、重复、不存在、虚拟文件系统目录都会被显式记录为“跳过原因”，
  而不是静默丢弃——审计时能回答“为什么这个命令没被看到”。
* 同一命令出现在多个目录时保留全部候选（含 PATH 顺序），不做覆盖。
* 扫描结果按 ``(name, path_index, path)`` 稳定排序，便于测试与审计。
"""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from .paths import is_inside, real_path

VIRTUAL_FS_ROOTS = ("/proc", "/sys", "/dev")

#: 除 PATH 之外额外补扫的标准命令目录。
#: 起因：系统服务/定时任务里的 PATH 常常很短（例如只有 /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin），
#: 只看 PATH 会“漏命令”。这里把这些标准位置默认并入扫描，保证“标准命令一个不落”；
#: 设 LCMD_INCLUDE_DEFAULT_DIRS=0 可关闭。
DEFAULT_COMMAND_DIRS: tuple[str, ...] = (
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/snap/bin",
    "/usr/local/games",
    "/usr/games",
)

SCAN_STATUS = (
    "scanned",
    "missing",
    "not_a_directory",
    "duplicate",
    "skipped_empty",
    "skipped_virtual_fs",
    "skipped_relative",
    "error",
)


@dataclass(frozen=True, slots=True)
class ScanDir:
    """PATH 中的一个目录条目及其处置结果。"""

    index: int
    raw: str
    path: str
    status: str
    note: str | None = None
    relative_to: str | None = None


@dataclass(frozen=True, slots=True)
class CandidateFile:
    """某个目录下的一个可执行文件候选。"""

    name: str
    path: str
    directory: str
    path_index: int
    is_symlink: bool
    symlink_target: str | None
    real_path: str | None


@dataclass(frozen=True, slots=True)
class DirScanResult:
    scan_dir: ScanDir
    candidates: tuple[CandidateFile, ...] = ()
    entries_scanned: int = 0
    executables_found: int = 0
    skipped_non_executable: int = 0
    skipped_not_regular: int = 0
    broken_symlinks: int = 0
    error: str | None = None


@dataclass(frozen=True, slots=True)
class DiscoverySnapshot:
    path_env: str
    dirs: tuple[ScanDir, ...]
    results: tuple[DirScanResult, ...]
    commands: tuple[tuple[str, tuple[CandidateFile, ...]], ...]
    built_at_monotonic: float
    scan_duration_ms: int

    def as_dict(self) -> dict[str, tuple[CandidateFile, ...]]:
        return dict(self.commands)

    def lookup(self, name: str) -> tuple[CandidateFile, ...]:
        for key, value in self.commands:
            if key == name:
                return value
        return ()


def build_scan_dirs(
    path_env: str,
    extra_dirs: Sequence[str] = (),
    base_cwd: str | None = None,
) -> tuple[ScanDir, ...]:
    """把 PATH 拆成规范化的目录列表，并标注跳过原因。

    跳过规则（安全默认）：
    * 空条目：POSIX 中代表 cwd，属于经典劫持向量，直接跳过。
    * 相对条目：解析结果依赖进程 cwd，直接跳过；需要时请用 LCMD_PATH 或
      LCMD_COMMAND_DIRS 显式给出绝对路径。
    * ``/proc``、``/sys``、``/dev``：虚拟文件系统，不扫描。
    * 与前面条目 realpath 相同的目录：标记 duplicate，不重复扫描。
    """
    base = base_cwd or os.getcwd()
    dirs: list[ScanDir] = []
    seen: dict[str, int] = {}
    index = 0

    def _add(raw: str, source: str) -> None:
        nonlocal index
        if raw == "":
            dirs.append(ScanDir(index=index, raw="", path="", status="skipped_empty", note="空 PATH 条目按 POSIX 等价于当前目录，出于安全默认跳过"))
            index += 1
            return

        expanded = os.path.expanduser(raw)
        if not os.path.isabs(expanded):
            resolved_rel = os.path.normpath(os.path.join(base, expanded))
            dirs.append(
                ScanDir(
                    index=index,
                    raw=raw,
                    path=resolved_rel,
                    status="skipped_relative",
                    note="相对 PATH 条目会随进程 cwd 漂移，默认跳过；请改用绝对路径",
                    relative_to=base,
                )
            )
            index += 1
            return

        normalized = os.path.normpath(expanded)
        real = real_path(normalized) or normalized

        for root in VIRTUAL_FS_ROOTS:
            if is_inside(normalized, root):
                dirs.append(
                    ScanDir(
                        index=index,
                        raw=raw,
                        path=normalized,
                        status="skipped_virtual_fs",
                        note=f"位于虚拟文件系统 {root}，不扫描",
                    )
                )
                index += 1
                return

        if real in seen:
            dirs.append(
                ScanDir(
                    index=index,
                    raw=raw,
                    path=normalized,
                    status="duplicate",
                    note=f"与第 {seen[real]} 个 PATH 条目指向同一目录，已跳过",
                )
            )
            index += 1
            return

        seen[real] = index
        if not os.path.lexists(normalized):
            status = "missing"
            note = "目录不存在"
        elif not os.path.isdir(normalized):
            status = "not_a_directory"
            note = "存在但不是目录"
        else:
            status = "scanned"
            note = f"来源：{source}"
        dirs.append(ScanDir(index=index, raw=raw, path=normalized, status=status, note=note))
        index += 1

    for raw in path_env.split(os.pathsep):
        _add(raw, "PATH")

    for raw in extra_dirs:
        _add(raw, "额外目录")

    return tuple(dirs)


def scan_directory(scan_dir: ScanDir) -> DirScanResult:
    """扫描单个目录中的可执行文件（不递归）。"""
    candidates: list[CandidateFile] = []
    entries = 0
    executables = 0
    non_executable = 0
    not_regular = 0
    broken = 0
    error: str | None = None

    try:
        entry_iter = os.scandir(scan_dir.path)
    except OSError as exc:
        return DirScanResult(
            scan_dir=scan_dir,
            error=f"{exc.strerror or exc.__class__.__name__} (errno={exc.errno})",
        )

    with entry_iter as it:
        for entry in it:
            entries += 1
            is_link = entry.is_symlink()
            try:
                st = entry.stat(follow_symlinks=True)
            except OSError:
                broken += 1
                continue
            if not stat.S_ISREG(st.st_mode):
                not_regular += 1
                continue
            path = os.path.join(scan_dir.path, entry.name)
            if not os.access(path, os.X_OK):
                non_executable += 1
                continue
            target = None
            if is_link:
                try:
                    target = os.readlink(path)
                except OSError:
                    target = None
            executables += 1
            candidates.append(
                CandidateFile(
                    name=entry.name,
                    path=path,
                    directory=scan_dir.path,
                    path_index=scan_dir.index,
                    is_symlink=is_link,
                    symlink_target=target,
                    real_path=real_path(path),
                )
            )

    candidates.sort(key=lambda c: (c.name, c.path))
    return DirScanResult(
        scan_dir=scan_dir,
        candidates=tuple(candidates),
        entries_scanned=entries,
        executables_found=executables,
        skipped_non_executable=non_executable,
        skipped_not_regular=not_regular,
        broken_symlinks=broken,
        error=error,
    )


def scan_path(
    path_env: str,
    extra_dirs: Sequence[str] = (),
    base_cwd: str | None = None,
) -> tuple[tuple[ScanDir, ...], tuple[DirScanResult, ...], dict[str, tuple[CandidateFile, ...]]]:
    """完整扫描：返回目录状态、逐目录统计、命令名 -> 候选列表。"""
    dirs = build_scan_dirs(path_env, extra_dirs=extra_dirs, base_cwd=base_cwd)
    results: list[DirScanResult] = []
    commands: dict[str, list[CandidateFile]] = {}

    for scan_dir in dirs:
        if scan_dir.status != "scanned":
            continue
        result = scan_directory(scan_dir)
        results.append(result)
        for candidate in result.candidates:
            commands.setdefault(candidate.name, []).append(candidate)

    ordered = {
        name: tuple(sorted(items, key=lambda c: (c.path_index, c.path)))
        for name, items in sorted(commands.items())
    }
    return dirs, tuple(results), ordered


class CommandDiscovery:
    """带 TTL 缓存的命令发现器。

    ``path_provider`` 每次刷新时调用，因此宿主进程 PATH 变化后最迟在 TTL
    之后可见；``refresh=True`` 可强制立即重扫。
    """

    def __init__(
        self,
        path_provider: Callable[[], str],
        extra_dirs: Sequence[str] = (),
        base_cwd: str | None = None,
        ttl_seconds: float = 5.0,
    ) -> None:
        self._path_provider = path_provider
        self._extra_dirs = tuple(extra_dirs)
        self._base_cwd = base_cwd
        self._ttl = max(0.0, ttl_seconds)
        self._cache_path: str | None = None
        self._cache_at: float = 0.0
        self._snapshot: DiscoverySnapshot | None = None

    def snapshot(self, refresh: bool = False) -> DiscoverySnapshot:
        path_env = self._path_provider()
        now = time.monotonic()
        cached = self._snapshot
        fresh = (
            cached is not None
            and not refresh
            and self._cache_path == path_env
            and (now - self._cache_at) <= self._ttl
        )
        if fresh:
            return cached

        t0 = time.monotonic()
        dirs, results, commands = scan_path(
            path_env,
            extra_dirs=self._extra_dirs,
            base_cwd=self._base_cwd,
        )
        snapshot = DiscoverySnapshot(
            path_env=path_env,
            dirs=dirs,
            results=results,
            commands=tuple(commands.items()),
            built_at_monotonic=now,
            scan_duration_ms=int((time.monotonic() - t0) * 1000),
        )
        self._snapshot = snapshot
        self._cache_path = path_env
        self._cache_at = now
        return snapshot

    def lookup(self, name: str, refresh: bool = False) -> tuple[CandidateFile, ...]:
        return self.snapshot(refresh=refresh).lookup(name)
