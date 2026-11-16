"""端到端协议测试：真的起一个子进程，走 stdio 握手与 tools/call。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_cli(args: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = dict(os.environ)
    merged.pop("LCMD_POLICY_MODE", None)
    if env:
        merged.update(env)
    return subprocess.run(
        [sys.executable, "-m", "linux_cmd_mcp", *args],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(ROOT),
        env=merged,
    )


def test_handshake_script_passes() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_handshake.py"), "--verbose"],
        capture_output=True,
        text=True,
        timeout=240,
        cwd=str(ROOT),
    )
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    for marker in (
        "PASS: initialize",
        "PASS: notifications/initialized",
        "PASS: tools/list",
        "PASS: tools/call execute_command",
        "PASS: stdout 纯净",
    ):
        assert marker in proc.stdout, proc.stdout


def test_check_config_outputs_json() -> None:
    proc = run_cli(["--check-config"])
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["transport"] == "sse"  # 默认传输已改为 SSE
    assert payload["http"]["host"] == "127.0.0.1"
    assert payload["http"]["port"] == 8765
    assert payload["http"]["auth_enabled"] is False
    assert "token" not in json.dumps(payload["http"]).lower()  # 摘要绝不回显令牌
    assert payload["policy"]["mode"] == "unrestricted"
    assert payload["command_count"] > 0
    assert payload["scanned_dirs"], "应至少有 1 个被扫描的 PATH 目录"
    assert payload["allowed_command_dirs"]


def test_version_flag() -> None:
    proc = run_cli(["--version"])
    assert proc.returncode == 0
    assert proc.stdout.strip().startswith("linux-cmd-mcp ")


def test_bad_policy_mode_fails_loudly() -> None:
    proc = run_cli(["--check-config"], env={"LCMD_POLICY_MODE": "yolo"})
    assert proc.returncode == 64
    assert "LCMD_POLICY_MODE" in proc.stderr
    assert proc.stdout.strip() == ""  # 诊断信息只走 stderr


def test_unsupported_transport_rejected() -> None:
    proc = run_cli(["--transport", "http", "--check-config"])
    # argparse 的非法枚举默认退 2；只要是“明确拒绝 + 指出唯一支持 stdio”即可
    assert proc.returncode in (2, 64)
    assert "stdio" in proc.stderr
    assert "invalid choice" in proc.stderr


async def test_bad_input_matrix_over_wire() -> None:
    """同进程走 call_tool，锁定“坏入参 → isError”的矩阵（不依赖子进程）。"""
    from linux_cmd_mcp.config import Settings
    from linux_cmd_mcp.server import build_server

    mcp = build_server(Settings.from_env({"LCMD_POLICY_MODE": "standard"}))
    matrix = [
        ("list_commands", {"limit": 0}),
        ("list_commands", {"limit": 2001}),
        ("describe_command", {"command": ""}),
        ("check_command", {"command": ""}),
        ("execute_command", {"command": ""}),
        ("execute_command", {"command": "echo", "timeout_seconds": 99999}),
        ("validate_working_directory", {"path": ""}),
    ]
    failures: list[str] = []
    for name, arguments in matrix:
        try:
            await mcp.call_tool(name, arguments)
        except Exception as exc:  # ToolError / ValidationError 都被 SDK 包成异常
            assert "Error executing tool" in str(exc) or "validation error" in str(exc), str(exc)
        else:
            failures.append(f"{name} {arguments} 未报错")
    assert not failures, failures

    # 无参数工具正常返回结构化内容
    result = await mcp.call_tool("get_system_info", {})
    payload = result[1]
    assert payload["kernel"]["sysname"] == "Linux"
