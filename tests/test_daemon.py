"""后台运行与监听地址测试：真实启动子进程、查状态、停止。"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from linux_cmd_mcp.config import Settings
from linux_cmd_mcp.daemon import resolve_paths, start_daemon
from linux_cmd_mcp.errors import ConfigError

ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run_cli(args: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = dict(os.environ)
    for key in ("LCMD_HTTP_HOST", "LCMD_HTTP_PORT", "LCMD_AUTH_TOKEN", "LCMD_STATE_DIR"):
        merged.pop(key, None)
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


def parse_json(proc: subprocess.CompletedProcess[str]) -> dict[str, object]:
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    return json.loads(proc.stdout)


def test_check_config_reflects_host_override() -> None:
    proc = run_cli(["--check-config", "--host", "0.0.0.0", "--port", "9123"])
    payload = parse_json(proc)
    assert payload["http"]["host"] == "0.0.0.0"
    assert payload["http"]["port"] == 9123


def test_daemon_command_lifecycle(tmp_path: Path) -> None:
    port = free_port()
    pid_file = tmp_path / "server.pid"
    log_file = tmp_path / "server.log"
    base = ["--host", "127.0.0.1", "--port", str(port), "--pid-file", str(pid_file), "--log-file", str(log_file)]

    started = run_cli(["--daemon", *base, "--startup-timeout", "15"], env={"LCMD_LOG_LEVEL": "ERROR"})
    payload = parse_json(started)
    try:
        assert payload["pid"] > 0
        assert payload["host"] == "127.0.0.1"
        assert payload["port"] == port
        assert payload["health"]["status"] == "ok"
        assert pid_file.exists()
        assert (pid_file.stat().st_mode & 0o077) == 0
        assert log_file.exists()

        status = run_cli(["--status", "--pid-file", str(pid_file)], env={"LCMD_LOG_LEVEL": "ERROR"})
        status_payload = parse_json(status)
        assert status_payload["running"] is True
        assert status_payload["healthy"] is True
        assert status_payload["health"]["bind_port"] == port
    finally:
        stopped = run_cli(["--stop", "--pid-file", str(pid_file)], env={"LCMD_LOG_LEVEL": "ERROR"})
        stop_payload = parse_json(stopped)
        assert stop_payload["stopped"] is True

    after = run_cli(["--status", "--pid-file", str(pid_file)], env={"LCMD_LOG_LEVEL": "ERROR"})
    assert after.returncode == 1
    assert json.loads(after.stdout)["running"] is False


def test_daemon_refuses_public_bind_without_token() -> None:
    settings = Settings.from_env({})
    with pytest.raises(ConfigError) as exc:
        start_daemon(settings, "sse", "0.0.0.0", free_port(), pid_file="/tmp/no-such-lcmd.pid")
    assert "LCMD_AUTH_TOKEN" in str(exc.value)


def test_daemon_rejects_stdio_transport() -> None:
    settings = Settings.from_env({})
    with pytest.raises(ConfigError) as exc:
        start_daemon(settings, "stdio", "127.0.0.1", free_port(), pid_file="/tmp/no-such-lcmd.pid")
    assert "stdio" in str(exc.value)


def test_state_paths_are_private_and_stable(tmp_path: Path) -> None:
    pid_path, log_path = resolve_paths(tmp_path / "run" / "server.pid", tmp_path / "run" / "server.log")
    assert pid_path == tmp_path / "run" / "server.pid"
    assert log_path == tmp_path / "run" / "server.log"
    assert not pid_path.exists()
