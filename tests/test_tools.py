"""工具层测试：6 个工具的 happy path、筛选/分页、状态码与坏入参。"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from linux_cmd_mcp.errors import ErrorCode, ToolFailure
from linux_cmd_mcp.inputs import (
    CheckCommandInput,
    DescribeCommandInput,
    ExecuteCommandInput,
    ListCommandsInput,
    ValidateWorkingDirectoryInput,
)
from linux_cmd_mcp.tools.check_command import check_command_impl
from linux_cmd_mcp.tools.describe_command import describe_command_impl
from linux_cmd_mcp.tools.execute_command import execute_command_impl
from linux_cmd_mcp.tools.get_system_info import get_system_info_impl
from linux_cmd_mcp.tools.list_commands import list_commands_impl
from linux_cmd_mcp.tools.validate_working_directory import validate_working_directory_impl


# --------------------------------------------------------------------------- list_commands


async def test_list_commands_keeps_duplicate_candidates(
    state_factory, fake_path_env: str, fake_bins
) -> None:
    state = state_factory(LCMD_PATH=fake_path_env, LCMD_ALLOWED_WORKDIRS=str(fake_bins.root))
    out = await list_commands_impl(state, ListCommandsInput(name_contains="tool-a", limit=10))
    assert out.total_matched == 2
    assert [c.path_index for c in out.commands] == [0, 5]
    assert out.commands[1].shadowed is True
    assert out.commands[0].shadowed is False


async def test_list_commands_reports_skipped_dirs(state_factory, fake_path_env: str, fake_bins) -> None:
    state = state_factory(LCMD_PATH=fake_path_env, LCMD_ALLOWED_WORKDIRS=str(fake_bins.root))
    out = await list_commands_impl(state, ListCommandsInput(limit=5))
    statuses = {d.status for d in out.skipped_dirs}
    assert {"duplicate", "missing", "skipped_relative", "skipped_virtual_fs"} <= statuses
    assert out.skipped_dir_count == len(out.skipped_dirs) >= 4


async def test_list_commands_filters_and_pagination(state_factory, fake_path_env: str, fake_bins) -> None:
    state = state_factory(LCMD_PATH=fake_path_env, LCMD_ALLOWED_WORKDIRS=str(fake_bins.root))
    page = await list_commands_impl(state, ListCommandsInput(limit=2, offset=0))
    assert page.returned == 2 and page.has_more is True and page.next_offset == 2

    by_dir = await list_commands_impl(state, ListCommandsInput(directory=str(fake_bins.bin2), limit=50))
    assert {c.directory for c in by_dir.commands} == {str(fake_bins.bin2)}

    denied = await list_commands_impl(state, ListCommandsInput(allowed=False, limit=50))
    assert all(c.denied for c in denied.commands)


async def test_list_commands_rejects_bad_directory(state_factory) -> None:
    state = state_factory(LCMD_PATH="/usr/bin")
    with pytest.raises(ToolFailure) as exc:
        await list_commands_impl(state, ListCommandsInput(directory=""))
    assert exc.value.code is ErrorCode.INVALID_ARGUMENT


# --------------------------------------------------------------------------- describe_command


async def test_describe_command_metadata(state_factory, fake_path_env: str, fake_bins) -> None:
    state = state_factory(LCMD_PATH=fake_path_env, LCMD_ALLOWED_WORKDIRS=str(fake_bins.root))
    out = await describe_command_impl(state, DescribeCommandInput(command="tool-a"))
    assert out.status == "ok"
    assert out.selected_path == str(fake_bins.tool_a1)
    assert out.stat is not None
    assert out.stat.mode_symbolic.startswith("-")
    assert out.stat.mode_octal == "0o0755"
    assert len(out.candidates) == 2
    assert any("候选" in note for note in out.notes)


async def test_describe_command_not_found(state_factory, fake_path_env: str) -> None:
    state = state_factory(LCMD_PATH=fake_path_env)

    with pytest.raises(ToolFailure) as exc:
        await describe_command_impl(state, DescribeCommandInput(command="no-such-cmd-xyz"))
    assert exc.value.code is ErrorCode.COMMAND_NOT_FOUND


async def test_describe_command_not_executable(state_factory, fake_bins) -> None:
    state = state_factory(LCMD_PATH=str(fake_bins.bin1))

    out = await describe_command_impl(state, DescribeCommandInput(command=str(fake_bins.bin1 / "tool-b")))
    assert out.exists is True
    assert out.executable is False
    assert out.status == "not_executable"


async def test_describe_command_symlink_chain(state_factory, fake_bins) -> None:
    state = state_factory(LCMD_PATH=str(fake_bins.bin1))

    out = await describe_command_impl(state, DescribeCommandInput(command="tool-c"))
    assert out.symlink_chain == [str(fake_bins.tool_c)]
    assert out.resolved_real_path == str(fake_bins.tool_c)


# --------------------------------------------------------------------------- check_command


async def test_check_command_missing_is_status_not_error(state_factory, fake_path_env: str) -> None:
    state = state_factory(LCMD_PATH=fake_path_env)

    out = await check_command_impl(state, CheckCommandInput(command="nope-xyz"))
    assert out.status == "not_found"
    assert out.exists is False and out.executable is False
    assert out.message


async def test_check_command_not_executable_and_denied(state_factory, fake_bins) -> None:
    state = state_factory(LCMD_PATH=str(fake_bins.bin1))

    out = await check_command_impl(state, CheckCommandInput(command="tool-b"))
    assert out.status == "not_found"  # 发现层只收可执行文件，裸名查不到

    out2 = await check_command_impl(state, CheckCommandInput(command=str(fake_bins.bin1 / "tool-b")))
    assert out2.status == "not_executable"


async def test_check_command_empty_input(state_factory) -> None:
    state = state_factory(LCMD_PATH="/usr/bin")

    with pytest.raises(ToolFailure) as exc:
        await check_command_impl(state, CheckCommandInput(command="  "))
    assert exc.value.code is ErrorCode.INVALID_ARGUMENT


# --------------------------------------------------------------------------- execute_command


def _real_state(state_factory, tmp_path: Path, **env: str):
    """默认用 standard 档位跑护栏相关断言；unrestricted 的行为另有专门测试。"""
    roots = f"{tmp_path},{os.getcwd()}"
    env.setdefault("LCMD_POLICY_MODE", "standard")
    return state_factory(LCMD_ALLOWED_WORKDIRS=roots, LCMD_MAX_TIMEOUT_SECONDS="30", **env)


async def test_execute_dry_run_does_not_start_process(state_factory, tmp_path: Path) -> None:
    state = _real_state(state_factory, tmp_path)

    target = tmp_path / "created-by-dry-run.txt"
    out = await execute_command_impl(
        state,
        ExecuteCommandInput(command="touch", args=[str(target)], cwd=str(tmp_path), dry_run=True),
    )
    assert out.dry_run is True
    assert target.exists() is False
    assert out.plan is not None
    assert out.plan.argv[0].startswith("/")
    assert os.path.realpath(out.plan.cwd) == os.path.realpath(str(tmp_path))
    assert "PATH" in out.plan.env_keys


async def test_execute_real_command_creates_file(state_factory, tmp_path: Path) -> None:
    state = _real_state(state_factory, tmp_path)

    target = tmp_path / "created.txt"
    out = await execute_command_impl(state, ExecuteCommandInput(command="touch", args=[str(target)]))
    assert out.exit_code == 0
    assert out.timed_out is False
    assert out.truncated is False
    assert target.exists()


async def test_execute_nonzero_exit_is_normal_result(state_factory, tmp_path: Path) -> None:
    state = _real_state(state_factory, tmp_path)

    out = await execute_command_impl(
        state,
        ExecuteCommandInput(command=sys.executable, args=["-c", "raise SystemExit(7)"]),
    )
    assert out.exit_code == 7
    assert out.signal_name is None


async def test_execute_timeout(state_factory, tmp_path: Path) -> None:
    state = _real_state(state_factory, tmp_path)

    out = await execute_command_impl(
        state,
        ExecuteCommandInput(command=sys.executable, args=["-c", "import time; time.sleep(10)"], timeout_seconds=0.4),
    )
    assert out.timed_out is True
    assert out.exit_code is None


async def test_execute_output_truncation(state_factory, tmp_path: Path) -> None:
    state = _real_state(state_factory, tmp_path)

    out = await execute_command_impl(
        state,
        ExecuteCommandInput(
            command=sys.executable,
            args=["-c", "print('y' * 2000)"],
            max_output_bytes=200,
        ),
    )
    assert out.stdout_truncated is True
    assert out.truncated is True
    assert len(out.stdout) == 200
    assert out.stdout_bytes >= 2000


async def test_execute_stdin(state_factory, tmp_path: Path) -> None:
    state = _real_state(state_factory, tmp_path)

    out = await execute_command_impl(
        state,
        ExecuteCommandInput(
            command=sys.executable,
            args=["-c", "import sys; print(sys.stdin.read().strip())"],
            stdin="payload",
        ),
    )
    assert out.stdout.strip() == "payload"


async def test_execute_policy_denied(state_factory, tmp_path: Path) -> None:
    state = _real_state(state_factory, tmp_path)

    with pytest.raises(ToolFailure) as exc:
        await execute_command_impl(state, ExecuteCommandInput(command="rm", args=["-rf", str(tmp_path)]))
    assert exc.value.code is ErrorCode.POLICY_DENIED
    assert exc.value.details["category"] == "file_delete"


async def test_execute_shell_wrapper_denied(state_factory, tmp_path: Path) -> None:
    state = _real_state(state_factory, tmp_path)

    with pytest.raises(ToolFailure) as exc:
        await execute_command_impl(state, ExecuteCommandInput(command="bash", args=["-c", "id"]))
    assert exc.value.code is ErrorCode.POLICY_DENIED
    assert exc.value.details["category"] == "shell_wrapper"


async def test_execute_env_injection_denied(state_factory, tmp_path: Path) -> None:
    state = _real_state(state_factory, tmp_path)

    with pytest.raises(ToolFailure) as exc:
        await execute_command_impl(
            state, ExecuteCommandInput(command="touch", args=[str(tmp_path / "x")], env={"LD_PRELOAD": "/tmp/e.so"})
        )
    assert exc.value.code is ErrorCode.ENV_KEY_FORBIDDEN


async def test_execute_cwd_outside_allowed_roots(state_factory, tmp_path: Path) -> None:
    state = _real_state(state_factory, tmp_path)

    with pytest.raises(ToolFailure) as exc:
        await execute_command_impl(state, ExecuteCommandInput(command="pwd", cwd="/tmp"))
    assert exc.value.code is ErrorCode.CWD_OUTSIDE_ALLOWED_ROOTS


async def test_execute_cwd_missing(state_factory, tmp_path: Path) -> None:
    state = _real_state(state_factory, tmp_path)

    with pytest.raises(ToolFailure) as exc:
        await execute_command_impl(
            state, ExecuteCommandInput(command="pwd", cwd=str(tmp_path / "missing"))
        )
    assert exc.value.code is ErrorCode.CWD_NOT_FOUND


async def test_execute_command_not_found(state_factory, tmp_path: Path) -> None:
    state = _real_state(state_factory, tmp_path)

    with pytest.raises(ToolFailure) as exc:
        await execute_command_impl(state, ExecuteCommandInput(command="definitely-not-a-command-xyz"))
    assert exc.value.code is ErrorCode.COMMAND_NOT_FOUND


async def test_execute_absolute_path_outside_command_dirs(state_factory, tmp_path: Path) -> None:
    script = tmp_path / "local-script"
    script.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    script.chmod(0o755)
    state = _real_state(state_factory, tmp_path)

    with pytest.raises(ToolFailure) as exc:
        await execute_command_impl(state, ExecuteCommandInput(command=str(script)))
    assert exc.value.code is ErrorCode.POLICY_DENIED
    assert exc.value.details["category"] == "path_forbidden"


# --------------------------------------------------------------------------- 其他工具


async def test_get_system_info(state_factory, tmp_path: Path) -> None:
    state = _real_state(state_factory, tmp_path)
    out = await get_system_info_impl(state)
    assert out.kernel.sysname == "Linux"
    assert out.cpu.logical_cores and out.cpu.logical_cores >= 1
    assert out.memory.total_bytes and out.memory.total_bytes > 0
    assert out.python_version.startswith("3.")
    assert isinstance(out.degraded, list)
    assert out.policy.mode == "standard"  # _real_state 显式指定了 standard
    # 不泄漏环境变量
    dumped = out.model_dump_json()
    assert "AWS_SECRET" not in dumped


async def test_validate_working_directory(state_factory, tmp_path: Path) -> None:
    state = _real_state(state_factory, tmp_path)
    out = await validate_working_directory_impl(
        state, ValidateWorkingDirectoryInput(path=str(tmp_path))
    )
    assert out.status == "ok"
    assert out.usable_as_cwd is True

    missing = await validate_working_directory_impl(
        state, ValidateWorkingDirectoryInput(path=str(tmp_path / "nope"))
    )
    assert missing.status == "not_found"


async def test_input_models_enforce_bounds() -> None:
    with pytest.raises(ValidationError):
        ListCommandsInput(limit=0)
    with pytest.raises(ValidationError):
        ListCommandsInput(limit=2001)
    assert ListCommandsInput(limit=2000).limit == 2000  # 上限抬到 2000 后 501 合法
    with pytest.raises(ValidationError):
        ListCommandsInput(unknown_field="x")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        ValidateWorkingDirectoryInput(path="x" * 5000)


async def test_execute_unrestricted_mode_is_ssh_equivalent(state_factory, tmp_path: Path) -> None:
    """默认档位下：shell 包装器、破坏性命令、任意绝对路径脚本都真的能跑。"""
    state = _real_state(state_factory, tmp_path, LCMD_POLICY_MODE="unrestricted")
    script = tmp_path / "local-script"
    script.write_text("#!/bin/sh\necho unrestricted-ok\n", encoding="utf-8")
    script.chmod(0o755)

    shell_out = await execute_command_impl(
        state, ExecuteCommandInput(command="sh", args=["-c", "printf shell-ok"], cwd=str(tmp_path))
    )
    assert shell_out.exit_code == 0
    assert shell_out.stdout == "shell-ok"

    script_out = await execute_command_impl(state, ExecuteCommandInput(command=str(script)))
    assert script_out.exit_code == 0
    assert script_out.stdout.strip() == "unrestricted-ok"

    rm_out = await execute_command_impl(
        state, ExecuteCommandInput(command="rm", args=[str(tmp_path / "missing-file")], dry_run=True)
    )
    assert rm_out.dry_run is True
    assert rm_out.resolved_path.endswith("/rm")


async def test_list_commands_enumerates_every_discovered_name(state_factory, tmp_path: Path) -> None:
    """limit=2000 + offset 分页必须能覆盖全部发现的命令名（不漏命令）。"""
    state = _real_state(state_factory, tmp_path, LCMD_POLICY_MODE="unrestricted")
    snapshot = state.discovery.snapshot()
    raw = snapshot.commands
    names = {item[0] for item in raw} if not isinstance(raw, dict) else set(raw)
    assert names, "发现结果为空"

    collected: set[str] = set()
    offset = 0
    for _ in range(20):  # 防御性上限，正常 1~2 页
        page = await list_commands_impl(state, ListCommandsInput(limit=2000, offset=offset))
        collected |= {candidate.name for candidate in page.commands}
        if not page.has_more:
            break
        offset = page.next_offset or 0
    assert names <= collected, f"漏掉命令：{sorted(names - collected)[:5]}"


async def test_check_and_execute_report_unrunnable_binary(state_factory, tmp_path: Path) -> None:
    """有 x 位但 shebang 解释器不存在：check 要说明原因，execute 要在启动前就拒绝。"""
    bad = tmp_path / "broken-tool"
    bad.write_text("#!/nonexistent/interp\nprint(1)\n", encoding="utf-8")
    bad.chmod(0o755)
    state = _real_state(state_factory, tmp_path, LCMD_POLICY_MODE="unrestricted")

    check = await check_command_impl(state, CheckCommandInput(command=str(bad)))
    assert check.exists is True
    assert check.executable is True  # 执行位在
    assert check.status == "not_executable"
    assert check.executability is not None
    assert check.executability.runnable is False
    assert "解释器不存在" in (check.executability.reason or "")
    assert "无法 exec" in check.message

    with pytest.raises(ToolFailure) as exc:
        await execute_command_impl(state, ExecuteCommandInput(command=str(bad)))
    assert exc.value.code is ErrorCode.COMMAND_NOT_EXECUTABLE
    assert exc.value.details["kind"] == "script"
    assert exc.value.details["interpreter"] == "/nonexistent/interp"

    described = await describe_command_impl(state, DescribeCommandInput(command=str(bad)))
    assert described.status == "not_executable"
    assert described.executability is not None and described.executability.runnable is False
    assert any("execve 会失败" in note for note in described.notes)


async def test_check_command_reports_runnable_for_normal_binary(state_factory, tmp_path: Path) -> None:
    state = _real_state(state_factory, tmp_path)
    check = await check_command_impl(state, CheckCommandInput(command="ls"))
    assert check.status == "ok"
    assert check.executability is not None and check.executability.runnable is True


async def test_list_commands_runnable_filter(state_factory, tmp_path: Path) -> None:
    """runnable 过滤必须与实际可执行性一致（起不来的命令能被单独列出来）。"""
    state = _real_state(state_factory, tmp_path, LCMD_POLICY_MODE="unrestricted")

    broken = await list_commands_impl(
        state, ListCommandsInput(runnable=False, limit=2000, refresh=True)
    )
    assert all(candidate.runnable is False for candidate in broken.commands)
    for candidate in broken.commands:
        assert candidate.unrunnable_reason, f"{candidate.path} 缺原因说明"

    healthy = await list_commands_impl(
        state, ListCommandsInput(runnable=True, limit=2000, refresh=True)
    )
    assert all(candidate.runnable is True for candidate in healthy.commands)
    assert healthy.total_matched > 0
    # 两个集合互补覆盖全部候选行
    assert healthy.total_matched + broken.total_matched >= len(state.discovery.snapshot().commands)


# --------------------------------------------------------------------------- 回归项


def test_long_absolute_command_path_is_accepted() -> None:
    """execute_command 的 command 上限必须与 describe/check 一致（PATH_MAX 级）。"""
    long_path = "/tmp/" + "a" * 400
    assert ExecuteCommandInput(command=long_path).command == long_path
    assert DescribeCommandInput(command=long_path).command == long_path


def test_symlink_chain_resolves_relative_targets(tmp_path) -> None:
    """相对目标的符号链接链必须按“链接所在目录”解析，不能在第一步就断。"""
    from linux_cmd_mcp.tools._common import symlink_chain

    (tmp_path / "sub").mkdir()
    (tmp_path / "real").write_text("", encoding="utf-8")
    (tmp_path / "sub" / "b").symlink_to("../real")
    (tmp_path / "sub" / "a").symlink_to("b")
    chain = symlink_chain(str(tmp_path / "sub" / "a"))
    assert chain == ["b", "../real"]
    assert symlink_chain(str(tmp_path / "real")) is None


async def test_execute_command_falls_back_when_server_cwd_disappears(
    state_factory, monkeypatch, python_executable
) -> None:
    """服务器 cwd 被删除时应结构化回退，而不是把裸 OSError 抛给协议层。"""
    state = state_factory(LCMD_POLICY_MODE="unrestricted")

    def _boom() -> str:
        raise OSError(2, "No such file or directory")

    monkeypatch.setattr("linux_cmd_mcp.tools.execute_command.os.getcwd", _boom)
    out = await execute_command_impl(
        state,
        ExecuteCommandInput(command=python_executable, args=["-c", "print('ok')"], cwd=None),
    )
    assert out.exit_code == 0
    assert out.stdout.strip() == "ok"
    assert out.cwd == "/"
    assert any("回退" in note for note in out.notes)


async def test_execute_command_reports_cwd_policy_after_fallback(
    state_factory, monkeypatch, python_executable
) -> None:
    """回退到 "/" 后仍要受 LCMD_ALLOWED_WORKDIRS 约束，并以结构化错误返回。"""
    from linux_cmd_mcp.errors import ToolFailure

    state = state_factory(LCMD_POLICY_MODE="unrestricted", LCMD_ALLOWED_WORKDIRS="/tmp")
    monkeypatch.setattr(
        "linux_cmd_mcp.tools.execute_command.os.getcwd",
        lambda: (_ for _ in ()).throw(OSError(2, "No such file or directory")),
    )
    with pytest.raises(ToolFailure) as exc:
        await execute_command_impl(state, ExecuteCommandInput(command=python_executable, cwd=None))
    assert exc.value.code is ErrorCode.CWD_NOT_ACCESSIBLE
    assert "显式传 cwd" in exc.value.hint
