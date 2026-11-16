"""路径规范化、越界判定与工作目录校验。

本模块是“路径相关判断”的唯一实现点，避免各工具对 `..`、`~`、
符号链接、相对路径给出不一致的结论。
"""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Sequence

from .models import WorkingDirectoryResult

_STATUS_BY_ERRNO = {
    errno.ENOENT: "not_found",
    errno.ENOTDIR: "not_a_directory",
    errno.EACCES: "permission_denied",
    errno.EPERM: "permission_denied",
    errno.ELOOP: "not_accessible",
    errno.ENAMETOOLONG: "invalid_path",
    errno.EINVAL: "invalid_path",
}


def normalize_absolute(raw: str, base: str | None = None) -> str:
    """把用户输入规范化成绝对路径。

    * 展开 ``~``
    * 相对路径基于 ``base``（默认服务器 cwd）解析
    * 不做 realpath（保留用户语义，供后续按需解析）

    Raises
    ------
    ValueError
        空路径、含 NUL 字节、或路径过长。
    """
    if not isinstance(raw, str):
        raise ValueError("path must be a string")
    if "\x00" in raw:
        raise ValueError("path contains a NUL byte")
    text = raw.strip()
    if not text:
        raise ValueError("path is empty")
    if len(text.encode("utf-8", "replace")) > 4096:
        raise ValueError("path is longer than 4096 bytes")
    text = os.path.expanduser(text)
    if not os.path.isabs(text):
        text = os.path.join(base or os.getcwd(), text)
    return os.path.normpath(text)


def real_path(path: str) -> str | None:
    """返回 realpath；遇到符号链接环等异常时返回 None（不抛异常）。"""
    try:
        return os.path.realpath(path, strict=False)
    except (OSError, RuntimeError, ValueError):
        return None


def is_inside(child: str, root: str) -> bool:
    """判断 ``child`` 是否位于 ``root`` 子树内（按 realpath 比较，兼容 '/'）。"""
    child_real = real_path(child) or child
    root_real = real_path(root) or root
    try:
        return os.path.commonpath([child_real, root_real]) == root_real
    except ValueError:  # 一个是相对路径或跨盘符（POSIX 下不会出现，防御性处理）
        return False


def match_root(child: str, roots: Sequence[str]) -> str | None:
    """返回命中的第一个允许根目录；``roots`` 为空时返回 None。"""
    for root in roots:
        if is_inside(child, root):
            return root
    return None


def file_type_of_mode(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "regular_file"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISBLK(mode):
        return "block_device"
    if stat.S_ISCHR(mode):
        return "character_device"
    return "unknown"


def permission_string(mode: int) -> str:
    """ls -l 风格的 10 位权限串。"""
    return stat.filemode(mode)


def validate_workdir(
    raw_path: str,
    allowed_roots: Sequence[str],
    require_write: bool = False,
    base: str | None = None,
    policy_summary: dict[str, object] | None = None,
) -> WorkingDirectoryResult:
    """校验一个目录能否作为子进程 cwd。

    返回结构化状态，而不是抛异常，便于调用方对每种情况分支处理。
    """
    checks: dict[str, str] = {
        "normalize": "not_checked",
        "resolve": "not_checked",
        "exists": "not_checked",
        "is_directory": "not_checked",
        "readable": "not_checked",
        "searchable": "not_checked",
        "writable": "not_checked",
        "within_allowed_roots": "not_checked",
    }
    policy = dict(policy_summary) if policy_summary else None

    def _result(
        status: str,
        message: str,
        *,
        path: str = raw_path,
        resolved: str | None = None,
        exists: bool = False,
        is_dir: bool = False,
        readable: bool = False,
        writable: bool = False,
        searchable: bool = False,
        usable: bool = False,
        within: str | None = None,
    ) -> WorkingDirectoryResult:
        return WorkingDirectoryResult(
            query=raw_path,
            path=path,
            resolved_path=resolved,
            status=status,  # type: ignore[arg-type]
            message=message,
            exists=exists,
            is_directory=is_dir,
            readable=readable,
            writable=writable,
            searchable=searchable,
            usable_as_cwd=usable,
            within_allowed_root=within,
            require_write=require_write,
            checks=checks,
            policy=policy,  # type: ignore[arg-type]
        )

    try:
        path = normalize_absolute(raw_path, base)
    except ValueError as exc:
        checks["normalize"] = "failed"
        return _result("invalid_path", f"路径非法：{exc}")

    checks["normalize"] = "ok"

    resolved = real_path(path)
    checks["resolve"] = "ok" if resolved else "failed"

    if not os.path.lexists(path):
        checks["exists"] = "failed"
        return _result(
            "not_found",
            f"路径不存在：{path}",
            path=path,
            resolved=resolved,
        )
    checks["exists"] = "ok"

    try:
        st = os.stat(path, follow_symlinks=True)
    except OSError as exc:
        status = _STATUS_BY_ERRNO.get(exc.errno or 0, "not_accessible")
        return _result(
            status,
            f"无法访问路径：{path}（{exc.strerror}）",
            path=path,
            resolved=resolved,
        )

    if not stat.S_ISDIR(st.st_mode):
        type_name = file_type_of_mode(st.st_mode)
        checks["is_directory"] = "failed"
        return _result(
            "not_a_directory",
            f"路径存在但不是目录（{type_name}）：{path}",
            path=path,
            resolved=resolved,
            exists=True,
        )
    checks["is_directory"] = "ok"

    readable = os.access(path, os.R_OK)
    searchable = os.access(path, os.X_OK)
    writable = os.access(path, os.W_OK)
    checks["readable"] = "ok" if readable else "failed"
    checks["searchable"] = "ok" if searchable else "failed"
    checks["writable"] = "ok" if writable else "failed"

    # 允许根目录限制（配置为空表示不限制）
    within: str | None = None
    if allowed_roots:
        within = match_root(path, allowed_roots)
        checks["within_allowed_roots"] = "ok" if within else "failed"
        if within is None:
            return _result(
                "outside_allowed_roots",
                f"目录不在允许的工作目录范围内：{path}",
                path=path,
                resolved=resolved,
                exists=True,
                is_dir=True,
                readable=readable,
                writable=writable,
                searchable=searchable,
            )
    else:
        checks["within_allowed_roots"] = "not_restricted"

    if not (readable and searchable):
        return _result(
            "permission_denied",
            f"目录权限不足（读={readable}, 执行={searchable}）：{path}",
            path=path,
            resolved=resolved,
            exists=True,
            is_dir=True,
            readable=readable,
            writable=writable,
            searchable=searchable,
            within=within,
        )

    if require_write and not writable:
        return _result(
            "not_writable",
            f"目录不可写：{path}",
            path=path,
            resolved=resolved,
            exists=True,
            is_dir=True,
            readable=readable,
            writable=writable,
            searchable=searchable,
            within=within,
        )

    return _result(
        "ok",
        f"目录可作为工作目录：{path}",
        path=path,
        resolved=resolved,
        exists=True,
        is_dir=True,
        readable=readable,
        writable=writable,
        searchable=searchable,
        usable=True,
        within=within,
    )


WORKDIR_STATUS_TO_ERROR = {
    "not_found": "CWD_NOT_FOUND",
    "not_a_directory": "CWD_NOT_A_DIRECTORY",
    "permission_denied": "CWD_PERMISSION_DENIED",
    "not_writable": "CWD_PERMISSION_DENIED",
    "outside_allowed_roots": "CWD_OUTSIDE_ALLOWED_ROOTS",
    "not_accessible": "CWD_NOT_ACCESSIBLE",
    "invalid_path": "INVALID_ARGUMENT",
}
