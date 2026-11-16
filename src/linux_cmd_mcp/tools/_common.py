"""工具层共用设施：状态注入、命令解析、候选富化、文件元信息。"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..discovery import CandidateFile, DirScanResult, ScanDir
from ..exec_probe import probe_executability
from ..errors import ErrorCode, fail
from ..models import (
    CommandCandidate,
    FileStatInfo,
    PolicySummary,
    ScanDirInfo,
    WorkingDirectoryResult,
)
from ..paths import file_type_of_mode, normalize_absolute, permission_string, real_path
from ..state import AppState

_STATE: AppState | None = None


def set_current_state(state: AppState) -> None:
    """由 server 在启动时注入；使工具在无请求上下文（如进程内测试）也能工作。"""
    global _STATE
    _STATE = state


def current_state() -> AppState:
    if _STATE is None:
        fail(
            ErrorCode.INTERNAL_ERROR,
            "服务器状态尚未初始化。",
            "通过 server.build_server()/main() 启动服务，或先调用 tools.set_current_state()。",
        )
    return _STATE


def get_state(ctx: Any | None) -> AppState:
    """优先取 lifespan 注入的 state，其次取进程内单例。"""
    if ctx is not None:
        try:
            request_context = ctx.request_context
        except Exception:  # 无请求上下文时 FastMCP 抛 ValueError
            request_context = None
        if request_context is not None:
            lifespan_state = getattr(request_context, "lifespan_context", None)
            if isinstance(lifespan_state, AppState):
                return lifespan_state
    return current_state()


def policy_summary(state: AppState) -> PolicySummary:
    return PolicySummary(**state.summary())  # type: ignore[arg-type]


# ----------------------------------------------------------------------- 发现


@dataclass(frozen=True, slots=True)
class ResolvedQuery:
    """一次命令查询的解析结果。"""

    query: str
    name: str
    is_path: bool
    candidates: tuple[CandidateFile, ...]

    @property
    def selected(self) -> CandidateFile | None:
        return self.candidates[0] if self.candidates else None


def resolve_candidates(state: AppState, query: str, refresh: bool = False) -> ResolvedQuery:
    """把 'ls' 或 '/usr/bin/ls' 解析成候选列表；不存在的路径返回空候选。"""
    if not isinstance(query, str):
        fail(ErrorCode.INVALID_ARGUMENT, "command 必须是字符串。", "传入命令名或绝对路径。", {})
    text = query.strip()
    if not text:
        fail(ErrorCode.INVALID_ARGUMENT, "command 不能为空。", "传入命令名，如 'ls'。", {})
    if text != query:
        fail(
            ErrorCode.INVALID_ARGUMENT,
            f"command 含首尾空白：{query!r}",
            "去掉首尾空白；参数请放到 args 数组。",
            {"command": query},
        )
    if "\x00" in text:
        fail(ErrorCode.INVALID_ARGUMENT, "command 含 NUL 字节。", "移除 NUL 字节。", {})

    if "/" in text:
        try:
            path = normalize_absolute(text)
        except ValueError as exc:
            fail(ErrorCode.INVALID_ARGUMENT, f"路径非法：{exc}", "传入绝对路径或命令名。", {"command": text})
        name = os.path.basename(path)
        if not name or name in {".", ".."}:
            fail(ErrorCode.INVALID_ARGUMENT, f"路径未指向具体文件：{path}", "路径必须以文件名结尾。", {"path": path})
        if not os.path.lexists(path):
            return ResolvedQuery(query=query, name=name, is_path=True, candidates=())
        is_link = os.path.islink(path)
        target = None
        if is_link:
            try:
                target = os.readlink(path)
            except OSError:
                target = None
        candidate = CandidateFile(
            name=name,
            path=path,
            directory=os.path.dirname(path) or "/",
            path_index=-1,
            is_symlink=is_link,
            symlink_target=target,
            real_path=real_path(path),
        )
        return ResolvedQuery(query=query, name=name, is_path=True, candidates=(candidate,))

    return ResolvedQuery(
        query=query,
        name=text,
        is_path=False,
        candidates=state.discovery.lookup(text, refresh=refresh),
    )


def require_candidates(state: AppState, query: str, refresh: bool = False) -> ResolvedQuery:
    resolved = resolve_candidates(state, query, refresh=refresh)
    if not resolved.candidates:
        fail(
            ErrorCode.COMMAND_NOT_FOUND,
            f"在 PATH 中找不到可执行文件：{resolved.name}",
            "用 list_commands 查看可用命令，或传入命令目录内的绝对路径（见 check_command）。",
            {
                "command": resolved.query,
                "name": resolved.name,
                "path_env": state.discovery.snapshot().path_env,
            },
        )
    return resolved


def enrich_candidates(
    state: AppState, resolved: ResolvedQuery, *, probe_exec: bool = False
) -> list[CommandCandidate]:
    """把发现结果转换成带策略判定与遮蔽信息的输出模型。

    ``probe_exec=True`` 时额外做静态 exec 解析（会读文件头，比纯 stat 慢一点），
    用于回答“这些命令里哪些实际起不来”。
    """
    result: list[CommandCandidate] = []
    earlier_indexes: dict[str, int] = {}
    for candidate in resolved.candidates:
        model = to_candidate(state, candidate, probe_exec=probe_exec)
        shadowed = False
        first = earlier_indexes.get(candidate.name)
        if first is not None and candidate.path_index > first and model.executable:
            shadowed = True
        earlier_indexes.setdefault(candidate.name, candidate.path_index)
        result.append(model.model_copy(update={"shadowed": shadowed}))
    return result


def to_candidate(state: AppState, candidate: CandidateFile, *, probe_exec: bool = False) -> CommandCandidate:
    decision = state.policy.evaluate(
        candidate.name,
        candidate.path,
        allowed_dirs=state.allowed_command_dirs,
    )
    executable = is_executable_file(candidate.path)
    runnable: bool | None = None
    unrunnable_reason: str | None = None
    if probe_exec:
        probe = probe_executability(candidate.path)
        runnable = probe.runnable
        unrunnable_reason = probe.reason
    return CommandCandidate(
        name=candidate.name,
        path=candidate.path,
        real_path=candidate.real_path,
        directory=candidate.directory,
        path_index=candidate.path_index,
        is_symlink=candidate.is_symlink,
        symlink_target=candidate.symlink_target,
        executable=executable,
        allowed=decision.allowed,
        denied=not decision.allowed,
        risk=decision.risk,  # type: ignore[arg-type]
        category=decision.category,
        shadowed=False,
        runnable=runnable,
        unrunnable_reason=unrunnable_reason,
    )


def is_executable_file(path: str) -> bool:
    try:
        st = os.stat(path)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and os.access(path, os.X_OK)


_is_executable_file = is_executable_file


def scan_dir_info(scan_dir: ScanDir, result: DirScanResult | None = None) -> ScanDirInfo:
    return ScanDirInfo(
        index=scan_dir.index,
        raw=scan_dir.raw,
        path=scan_dir.path,
        status=scan_dir.status,  # type: ignore[arg-type]
        note=scan_dir.note,
        entries_scanned=result.entries_scanned if result else 0,
        executables_found=result.executables_found if result else 0,
        skipped_non_executable=result.skipped_non_executable if result else 0,
        broken_symlinks=result.broken_symlinks if result else 0,
    )


# ----------------------------------------------------------------------- 文件元信息


def file_stat(path: str) -> FileStatInfo | None:
    """返回跟随符号链接后的 stat 信息；文件不可访问时返回 None。"""
    try:
        st = os.stat(path)
    except OSError:
        return None

    try:
        import pwd

        owner = pwd.getpwuid(st.st_uid).pw_name
    except (KeyError, ImportError, OSError):
        owner = None
    try:
        import grp

        group = grp.getgrgid(st.st_gid).gr_name
    except (KeyError, ImportError, OSError):
        group = None

    return FileStatInfo(
        path=path,
        real_path=real_path(path),
        file_type=file_type_of_mode(st.st_mode),  # type: ignore[arg-type]
        size_bytes=st.st_size,
        mode_octal=f"0o{stat.S_IMODE(st.st_mode):04o}",
        mode_symbolic=permission_string(st.st_mode),
        uid=st.st_uid,
        gid=st.st_gid,
        owner=owner,
        group=group,
        owner_lookup_error=None if (owner and group) else "pwd/grp 查询失败，仅返回 uid/gid",
        mtime_iso=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(timespec="seconds"),
        inode=st.st_ino,
    )


def symlink_chain(path: str, max_hops: int = 16) -> list[str] | None:
    """返回逐级 readlink 的目标；不是符号链接时返回 None。

    相对目标必须相对于**链接所在目录**解析，而不是服务器进程 cwd——否则
    ``a -> b``、``b -> ../real`` 这类同目录链条会在第一步就断掉。
    同时用已访问 realpath 集合防御符号链接环。
    """
    if not os.path.islink(path):
        return None
    chain: list[str] = []
    current = os.path.abspath(path)
    visited: set[str] = set()
    for _ in range(max_hops):
        if current in visited:  # 用链接自身的路径判环，realpath 会把 a->b->real 误判成环
            break
        visited.add(current)
        try:
            target = os.readlink(current)
        except OSError:
            break
        chain.append(target)
        next_path = target if os.path.isabs(target) else os.path.join(os.path.dirname(current), target)
        current = os.path.normpath(next_path)
        if not os.path.islink(current):
            break
    return chain


WORKDIR_STATUS_TO_CODE = {
    "not_found": ErrorCode.CWD_NOT_FOUND,
    "not_a_directory": ErrorCode.CWD_NOT_A_DIRECTORY,
    "permission_denied": ErrorCode.CWD_PERMISSION_DENIED,
    "not_writable": ErrorCode.CWD_PERMISSION_DENIED,
    "outside_allowed_roots": ErrorCode.CWD_OUTSIDE_ALLOWED_ROOTS,
    "not_accessible": ErrorCode.CWD_NOT_ACCESSIBLE,
    "invalid_path": ErrorCode.INVALID_ARGUMENT,
}


def fail_on_workdir(result: WorkingDirectoryResult) -> None:
    """把工作目录校验失败转换成结构化异常（execute_command 启动前调用）。"""
    if result.status == "ok":
        return
    code = WORKDIR_STATUS_TO_CODE.get(result.status, ErrorCode.CWD_NOT_ACCESSIBLE)
    fail(
        code,
        result.message,
        _workdir_hint(result),
        {
            "cwd": result.path,
            "resolved": result.resolved_path,
            "checks": result.checks,
            "allowed_roots": list(result.policy.allowed_workdirs),
        },
    )


def _workdir_hint(result: WorkingDirectoryResult) -> str:
    hints = {
        "not_found": "先创建目录（mkdir -p），或改用已存在的工作目录。",
        "not_a_directory": "传入目录而不是文件；用 validate_working_directory 复核。",
        "permission_denied": "选择当前用户可读且可进入的目录；不要在不可执行权限的目录里启动进程。",
        "not_writable": "该场景需要可写目录，换用可写路径或调整权限。",
        "outside_allowed_roots": "使用 LCMD_ALLOWED_WORKDIRS 中的目录；越界路径一律拒绝。",
        "not_accessible": "路径中存在符号链接环或不可穿越的组件；改用真实路径重试。",
        "invalid_path": "修正路径格式（空值、NUL、超长都会拒绝）。",
    }
    return hints.get(result.status, "用 validate_working_directory 复核路径。")
