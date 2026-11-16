"""子进程执行器：execve 语义、超时、输出限额、取消与进程组回收。

关键约束（与 docs/POLICY.md 一致）：

* 只用 ``asyncio.create_subprocess_exec``，参数数组传递，绝不拼 shell 字符串，
  绝不使用 ``shell=True``。
* ``start_new_session=True``：子进程自成进程组，超时/取消时按组发信号，
  避免 ``sh -c`` 风格的孙进程残留。
* stdout/stderr 分别按字节上限截断：超出部分继续读取但丢弃，既保证子进程
  不被管道阻塞，也保证内存可控。
* 取消（客户端 ``notifications/cancelled`` 或任务被 cancel）时先 SIGTERM，
  再 SIGKILL，并在 ``finally`` 中兜底，避免遗留孤儿进程。
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .errors import ErrorCode, fail

_READ_CHUNK = 64 * 1024
_TERM_GRACE_SECONDS = 1.0


@dataclass(slots=True)
class RunSpec:
    """一次执行的完整、已校验的输入。"""

    command: str
    argv: tuple[str, ...]
    resolved_path: str
    cwd: str
    env: dict[str, str]
    timeout_seconds: float
    max_output_bytes: int
    stdin_text: str | None


@dataclass(slots=True)
class StreamCapture:
    data: bytes
    total_bytes: int
    truncated: bool
    lossy: bool = False


@dataclass(slots=True)
class ExecutionResult:
    exit_code: int | None
    signal_name: str | None
    stdout: str
    stderr: str
    stdout_bytes: int
    stderr_bytes: int
    stdout_truncated: bool
    stderr_truncated: bool
    duration_ms: int
    timed_out: bool
    started_at: str
    finished_at: str
    decoded_with_replacement: bool


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _signal_name(returncode: int) -> str | None:
    if returncode >= 0:
        return None
    number = -returncode
    try:
        return signal.Signals(number).name
    except ValueError:
        return f"SIG{number}"


async def _drain(stream: asyncio.StreamReader, cap: int) -> StreamCapture:
    """读取一条输出流：保留前 ``cap`` 字节，其余继续读并丢弃。"""
    kept: list[bytes] = []
    kept_bytes = 0
    total = 0
    truncated = False
    while True:
        try:
            chunk = await stream.read(_READ_CHUNK)
        except (asyncio.LimitOverrunError, ValueError):
            truncated = True
            break
        if not chunk:
            break
        total += len(chunk)
        if kept_bytes < cap:
            room = cap - kept_bytes
            kept.append(chunk[:room])
            kept_bytes += min(room, len(chunk))
            if len(chunk) > room:
                truncated = True
        else:
            truncated = True
    return StreamCapture(data=b"".join(kept), total_bytes=total, truncated=truncated)


async def _feed_stdin(stream: asyncio.StreamWriter, text: str) -> None:
    """把文本写入 stdin 并关闭；对端提前退出（BrokenPipe）不算错误。"""
    try:
        stream.write(text.encode("utf-8"))
        await stream.drain()
    except (BrokenPipeError, ConnectionResetError, asyncio.IncompleteReadError):
        pass
    finally:
        with contextlib.suppress(Exception):
            stream.close()


def _kill_group(proc: asyncio.subprocess.Process, sig: signal.Signals) -> None:
    """按进程组发信号；进程已退出或权限不足时安静返回。"""
    if proc.returncode is not None:
        return
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, PermissionError, OSError):
        pgid = None
    if pgid is not None:
        try:
            os.killpg(pgid, sig)
            return
        except (ProcessLookupError, PermissionError, OSError):
            pass
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        proc.send_signal(sig)


async def _terminate(proc: asyncio.subprocess.Process, grace: float = _TERM_GRACE_SECONDS) -> None:
    """SIGTERM -> 等待 grace -> SIGKILL，确保进程组被回收。"""
    if proc.returncode is not None:
        return
    _kill_group(proc, signal.SIGTERM)
    try:
        await asyncio.wait_for(asyncio.shield(proc.wait()), grace)
        return
    except (asyncio.TimeoutError, asyncio.CancelledError):
        pass
    _kill_group(proc, signal.SIGKILL)
    with contextlib.suppress(asyncio.TimeoutError, asyncio.CancelledError):
        await asyncio.wait_for(proc.wait(), 5.0)


async def _shielded_terminate(proc: asyncio.subprocess.Process, grace: float = _TERM_GRACE_SECONDS) -> None:
    """在取消语境下也尽量完成回收；外层被再次取消时同步补一记 SIGKILL。"""
    task = asyncio.ensure_future(_terminate(proc, grace))
    try:
        await asyncio.shield(task)
    except asyncio.CancelledError:
        _kill_group(proc, signal.SIGKILL)
        raise


def _progress_token(ctx: Any) -> Any:
    if ctx is None:
        return None
    try:
        meta = ctx.request_context.meta
    except Exception:  # noqa: BLE001 - 无请求上下文时安静降级
        return None
    return getattr(meta, "progressToken", None) if meta is not None else None


async def _progress_loop(ctx: Any, spec: RunSpec, started: float) -> None:
    """长任务每 0.5s 发一次 notifications/progress。"""
    try:
        while True:
            await asyncio.sleep(0.5)
            elapsed = time.monotonic() - started
            await ctx.report_progress(
                progress=round(elapsed, 2),
                total=spec.timeout_seconds,
                message=f"running {spec.command} ({elapsed:.1f}s)",
            )
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001 - 进度通知是尽力而为
        return


def _raise_spawn_error(exc: OSError, spec: RunSpec) -> None:
    err = exc.errno or 0
    cwd_exists = os.path.isdir(spec.cwd)
    hint_cwd = (
        "工作目录已校验通过，但启动瞬间消失或不可访问；请重新校验 cwd。"
        if not cwd_exists
        else "检查可执行文件的权限、解释器行（#!）与文件系统挂载状态。"
    )
    mapping: dict[int, tuple[ErrorCode, str]] = {
        errno.ENOENT: (
            ErrorCode.COMMAND_NOT_FOUND,
            f"启动失败：execve 报 ENOENT——可执行文件或它的动态加载器/shebang 解释器不存在"
            f"（cwd 存在={cwd_exists}）。用 check_command 的 executability 字段确认是哪种。",
        ),
        errno.EACCES: (ErrorCode.COMMAND_NOT_EXECUTABLE, "启动失败：可执行文件缺少执行权限。"),
        errno.ENOTDIR: (ErrorCode.CWD_NOT_A_DIRECTORY, "启动失败：工作目录路径中有非目录组件。"),
        errno.ENOEXEC: (ErrorCode.SPAWN_FAILED, "启动失败：文件格式不可执行（坏的 shebang 或二进制格式不符）。"),
        errno.E2BIG: (ErrorCode.LIMIT_EXCEEDED, "启动失败：argv/环境变量总长度超过内核限制。"),
        errno.EMFILE: (ErrorCode.SPAWN_FAILED, "启动失败：进程打开文件数达到上限（EMFILE）。"),
        errno.ENFILE: (ErrorCode.SPAWN_FAILED, "启动失败：系统打开文件数达到上限（ENFILE）。"),
        errno.ELOOP: (ErrorCode.SPAWN_FAILED, "启动失败：符号链接层级过深（ELOOP）。"),
        errno.ENOMEM: (ErrorCode.SPAWN_FAILED, "启动失败：内存不足（ENOMEM）。"),
    }
    code, message = mapping.get(err, (ErrorCode.SPAWN_FAILED, f"启动失败：{exc.strerror or exc}"))
    fail(code, message, hint_cwd, {"errno": err, "errno_name": errno.errorcode.get(err, "?"), "argv0": spec.argv[0] if spec.argv else spec.command, "cwd": spec.cwd})


def _decode(data: bytes) -> tuple[str, bool]:
    try:
        return data.decode("utf-8"), False
    except UnicodeDecodeError:
        return data.decode("utf-8", "replace"), True


async def run_command(spec: RunSpec, ctx: Any | None = None) -> ExecutionResult:
    """执行一条已校验的命令，返回结构化结果。

    调用方负责完成：命令解析、策略判定、cwd/env/限额校验。本函数只负责
    “按 execve 语义启动、限时、限流、回收”。
    """
    started_at = _now_iso()
    t0 = time.monotonic()

    try:
        proc = await asyncio.create_subprocess_exec(
            *spec.argv,
            stdin=asyncio.subprocess.PIPE if spec.stdin_text is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=spec.cwd,
            env=spec.env,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        _raise_spawn_error(exc, spec)
        raise  # pragma: no cover - _raise_spawn_error 必然抛出
    except (ValueError, NotImplementedError, subprocess.SubprocessError) as exc:
        fail(
            ErrorCode.SPAWN_FAILED,
            f"启动失败：{exc.__class__.__name__}: {exc}",
            "检查 argv、环境变量与平台能力。",
            {"command": spec.command},
        )
        raise  # pragma: no cover

    stdout_task = asyncio.create_task(_drain(proc.stdout, spec.max_output_bytes))  # type: ignore[arg-type]
    stderr_task = asyncio.create_task(_drain(proc.stderr, spec.max_output_bytes))  # type: ignore[arg-type]

    stdin_task: asyncio.Task[None] | None = None
    if spec.stdin_text is not None and proc.stdin is not None:
        stdin_task = asyncio.create_task(_feed_stdin(proc.stdin, spec.stdin_text))

    progress_task: asyncio.Task[None] | None = None
    if _progress_token(ctx) is not None:
        progress_task = asyncio.create_task(_progress_loop(ctx, spec, t0))

    timed_out = False
    try:
        try:
            await asyncio.wait_for(proc.wait(), spec.timeout_seconds)
        except asyncio.TimeoutError:
            timed_out = True
    finally:
        if progress_task is not None:
            progress_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await progress_task
        if proc.returncode is None:
            await _shielded_terminate(proc)
        if stdin_task is not None and not stdin_task.done():
            stdin_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await stdin_task

    out_capture, err_capture = await asyncio.gather(stdout_task, stderr_task)

    stdout, stdout_lossy = _decode(out_capture.data)
    stderr, stderr_lossy = _decode(err_capture.data)

    finished_at = _now_iso()
    return ExecutionResult(
        exit_code=proc.returncode if proc.returncode is not None and proc.returncode >= 0 else None,
        signal_name=_signal_name(proc.returncode or 0),
        stdout=stdout,
        stderr=stderr,
        stdout_bytes=out_capture.total_bytes,
        stderr_bytes=err_capture.total_bytes,
        stdout_truncated=out_capture.truncated,
        stderr_truncated=err_capture.truncated,
        duration_ms=int((time.monotonic() - t0) * 1000),
        timed_out=timed_out,
        started_at=started_at,
        finished_at=finished_at,
        decoded_with_replacement=stdout_lossy or stderr_lossy,
    )
