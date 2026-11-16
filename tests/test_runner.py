"""执行器测试：输出、退出码、超时、截断、stdin、spawn 失败与取消回收。"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest

from linux_cmd_mcp.errors import ErrorCode, ToolFailure
from linux_cmd_mcp.runner import RunSpec, run_command


def make_spec(
    cwd: Path | str,
    argv: list[str],
    *,
    timeout: float = 10.0,
    cap: int = 1024 * 1024,
    stdin: str | None = None,
    env: dict[str, str] | None = None,
) -> RunSpec:
    return RunSpec(
        command=argv[0],
        argv=tuple(argv),
        resolved_path=argv[0],
        cwd=str(cwd),
        env=env or {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp")},
        timeout_seconds=timeout,
        max_output_bytes=cap,
        stdin_text=stdin,
    )


async def test_stdout_stderr_and_exit_code(tmp_path: Path) -> None:
    result = await run_command(
        make_spec(tmp_path, [sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr)"])
    )
    assert result.exit_code == 0
    assert result.stdout == "out\n"
    assert result.stderr == "err\n"
    assert result.timed_out is False
    assert result.duration_ms >= 0
    assert result.started_at.endswith("+00:00")


async def test_nonzero_exit_is_not_an_error(tmp_path: Path) -> None:
    result = await run_command(make_spec(tmp_path, [sys.executable, "-c", "raise SystemExit(3)"]))
    assert result.exit_code == 3
    assert result.signal_name is None


async def test_signal_termination_is_reported(tmp_path: Path) -> None:
    code = "import os, signal; os.kill(os.getpid(), signal.SIGKILL)"
    result = await run_command(make_spec(tmp_path, [sys.executable, "-c", code]))
    assert result.exit_code is None
    assert result.signal_name == "SIGKILL"


async def test_timeout_marks_timed_out_and_kills_group(tmp_path: Path) -> None:
    started = asyncio.get_running_loop().time()
    result = await run_command(
        make_spec(tmp_path, [sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.4)
    )
    elapsed = asyncio.get_running_loop().time() - started
    assert result.timed_out is True
    assert result.exit_code is None
    assert elapsed < 5.0  # 没有被 sleep(30) 拖住


async def test_output_truncation_keeps_prefix_and_counts_total(tmp_path: Path) -> None:
    result = await run_command(
        make_spec(tmp_path, [sys.executable, "-c", "print('x' * 600)"], cap=100)
    )
    assert result.stdout_truncated is True
    assert len(result.stdout) == 100
    assert result.stdout_bytes >= 600
    assert result.stdout.startswith("xxxx")


async def test_stdout_and_stderr_have_independent_caps(tmp_path: Path) -> None:
    code = "import sys; print('a'*50); print('b'*500, file=sys.stderr)"
    result = await run_command(make_spec(tmp_path, [sys.executable, "-c", code], cap=60))
    assert result.stdout_truncated is False
    assert result.stderr_truncated is True
    assert result.stderr_bytes >= 500


async def test_stdin_is_written_and_closed(tmp_path: Path) -> None:
    code = "import sys; data = sys.stdin.read(); print(data.upper())"
    result = await run_command(make_spec(tmp_path, [sys.executable, "-c", code], stdin="abc"))
    assert result.exit_code == 0
    assert result.stdout.strip() == "ABC"


async def test_no_stdin_means_devnull(tmp_path: Path) -> None:
    code = "import sys; print('EOF' if sys.stdin.read() == '' else 'DATA')"
    result = await run_command(make_spec(tmp_path, [sys.executable, "-c", code]))
    assert result.stdout.strip() == "EOF"


async def test_cwd_is_applied(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    result = await run_command(make_spec(work, [sys.executable, "-c", "import os; print(os.getcwd())"]))
    assert result.stdout.strip() == str(work)


async def test_environment_is_exactly_what_is_passed(tmp_path: Path) -> None:
    code = "import os; print(os.environ.get('LCMD_TEST_FLAG', 'missing'))"
    result = await run_command(
        make_spec(tmp_path, [sys.executable, "-c", code], env={"PATH": os.environ.get("PATH", ""), "LCMD_TEST_FLAG": "1"})
    )
    assert result.stdout.strip() == "1"


async def test_spawn_failure_is_structured(tmp_path: Path) -> None:
    with pytest.raises(ToolFailure) as exc:
        await run_command(make_spec(tmp_path, ["/nonexistent/binary-xyz"], timeout=5))
    assert exc.value.code is ErrorCode.COMMAND_NOT_FOUND
    assert exc.value.details["errno"] == 2


async def test_cancellation_kills_child_process(tmp_path: Path) -> None:
    pid_file = tmp_path / "child.pid"
    code = (
        "import os, time\n"
        f"open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
        "time.sleep(30)\n"
    )
    task = asyncio.create_task(run_command(make_spec(tmp_path, [sys.executable, "-c", code], timeout=60)))

    for _ in range(100):
        if pid_file.exists() and pid_file.read_text().strip():
            break
        await asyncio.sleep(0.05)
    else:
        task.cancel()
        pytest.fail("子进程未启动")

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    pid = int(pid_file.read_text().strip())
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        await asyncio.sleep(0.1)
    else:
        pytest.fail(f"取消后子进程 {pid} 仍存在（孤儿进程）")
