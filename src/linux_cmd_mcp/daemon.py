"""后台运行、状态查询与停止。

只支持 Linux：通过 ``subprocess.Popen`` 启动一个脱离终端的子进程，父进程
等待 ``/healthz`` 就绪后写 PID 文件并返回。这里不调用 ``fork``，也不改
进程的会话/终端控制，避免与 uvicorn 的信号处理互相干扰。

PID 文件保存的是 JSON（不是裸 PID），包含 host/port/transport/日志路径，
方便 ``--status`` 在不读取环境变量的情况下判断“这个 PID 到底是不是本服务”。
文件权限固定为 0600，目录为 0700。
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener

from . import __version__
from .config import Settings
from .errors import ConfigError

STATE_VERSION = 1
DEFAULT_STARTUP_TIMEOUT = 8.0
DEFAULT_STOP_TIMEOUT = 10.0
LOOPBACK_BIND_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _state_dir() -> Path:
    explicit = os.environ.get("LCMD_STATE_DIR")
    if explicit:
        return Path(explicit).expanduser()
    xdg = os.environ.get("XDG_STATE_HOME")
    if xdg:
        return Path(xdg).expanduser() / "linux-cmd-mcp"
    return Path.home() / ".local" / "state" / "linux-cmd-mcp"


def resolve_paths(pid_file: str | Path | None = None, log_file: str | Path | None = None) -> tuple[Path, Path]:
    """返回 (pid_file, log_file)；未显式指定时放在用户 state 目录。"""
    base = _state_dir()
    pid_path = Path(pid_file).expanduser() if pid_file else base / "server.pid"
    log_path = Path(log_file).expanduser() if log_file else base / "server.log"
    return pid_path, log_path


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def read_state(pid_file: str | Path | None = None) -> dict[str, Any] | None:
    path, _ = resolve_paths(pid_file)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("pid"), int):
        return None
    return payload


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # 进程存在但不属于当前用户；不能确认身份时按“存在但不可控”处理。
        return True
    return True


def _pid_matches(pid: int) -> bool:
    """确认 PID 是本服务进程，避免 PID 复用后误杀别的程序。"""
    if not _pid_alive(pid):
        return False
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return False
    argv = [part for part in raw.split(b"\0") if part]
    joined = b" ".join(argv)
    return b"linux_cmd_mcp" in joined and b"--daemon" not in joined


def _tail(path: Path, lines: int = 12) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return "\n".join(text.splitlines()[-lines:])


def _probe_host(host: str) -> str:
    if host in {"0.0.0.0", "::", "[::]"}:
        return "::1" if host in {"::", "[::]"} else "127.0.0.1"
    if host == "localhost":
        return "127.0.0.1"
    return host


def _health_url(host: str, port: int) -> str:
    probe = _probe_host(host)
    if ":" in probe and not probe.startswith("["):
        probe = f"[{probe}]"
    return f"http://{probe}:{port}/healthz"


def probe_health(host: str, port: int, timeout: float = 0.8) -> dict[str, Any] | None:
    """访问 /healthz；连接失败或返回非 JSON 时返回 None。"""
    opener = build_opener(ProxyHandler({}))  # 忽略 http_proxy，避免本机代理劫持
    request = Request(_health_url(host, port), headers={"Accept": "application/json"})
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                return None
            payload = json.loads(response.read().decode("utf-8"))
            return payload if isinstance(payload, dict) else None
    except (URLError, OSError, ValueError, json.JSONDecodeError):
        return None


def _preflight(settings: Settings, transport: str, host: str, port: int) -> None:
    if transport == "stdio":
        raise ConfigError(
            "--daemon 不支持 stdio 传输",
            "stdio 由宿主进程直接拉起；后台常驻请用 --transport sse 或 streamable-http。",
        )
    if not host or any(ch.isspace() for ch in host):
        raise ConfigError(f"监听地址 {host!r} 非法", "写 IP 或主机名，例如 127.0.0.1、0.0.0.0、192.168.1.20")
    if not 1 <= port <= 65535:
        raise ConfigError(f"端口 {port} 非法", "端口必须在 1..65535 之间。")
    if host not in LOOPBACK_BIND_HOSTS and settings.auth_token is None:
        raise ConfigError(
            f"拒绝在 {host} 上无鉴权后台启动",
            "先设置 LCMD_AUTH_TOKEN（至少 16 字符，建议 openssl rand -hex 32），或改绑 127.0.0.1。",
        )


def start_daemon(
    settings: Settings,
    transport: str,
    host: str,
    port: int,
    *,
    pid_file: str | Path | None = None,
    log_file: str | Path | None = None,
    startup_timeout: float = DEFAULT_STARTUP_TIMEOUT,
    log_level: str | None = None,
) -> dict[str, Any]:
    """启动后台服务，等到 /healthz 可用后返回状态字典。"""
    _preflight(settings, transport, host, port)

    pid_path, log_path = resolve_paths(pid_file, log_file)
    existing = read_state(pid_path)
    if existing and _pid_matches(int(existing["pid"])):
        raise ConfigError(
            f"已有实例在运行：pid={existing['pid']}",
            f"先执行 --stop，或换 --pid-file；状态文件：{pid_path}",
        )
    if existing:
        with_remove = pid_path
        with_remove.unlink(missing_ok=True)

    log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    log_path.touch(mode=0o600, exist_ok=True)
    os.chmod(log_path, 0o600)

    cmd = [
        sys.executable,
        "-m",
        "linux_cmd_mcp",
        "--transport",
        transport,
        "--host",
        host,
        "--port",
        str(port),
    ]
    if log_level:
        cmd.extend(["--log-level", log_level])

    env = dict(os.environ)
    env["LCMD_DAEMON_CHILD"] = "1"

    log_handle = log_path.open("ab")
    try:
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=log_handle,
            start_new_session=True,
            close_fds=True,
            env=env,
        )
    finally:
        log_handle.close()

    state: dict[str, Any] = {
        "version": STATE_VERSION,
        "service": "linux-cmd-mcp",
        "service_version": __version__,
        "pid": process.pid,
        "host": host,
        "port": port,
        "transport": transport,
        "log_file": str(log_path),
        "pid_file": str(pid_path),
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    _atomic_write_json(pid_path, state)

    deadline = time.monotonic() + max(0.5, startup_timeout)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            pid_path.unlink(missing_ok=True)
            raise ConfigError(
                f"后台进程提前退出（exit={process.returncode}）",
                f"查看日志：{log_path}\n{_tail(log_path)}",
            )
        health = probe_health(host, port, timeout=0.8)
        if health and health.get("status") == "ok":
            state["health"] = health
            _atomic_write_json(pid_path, state)
            return state
        time.sleep(0.2)

    _kill(process.pid, timeout=3.0)
    pid_path.unlink(missing_ok=True)
    raise ConfigError(
        f"后台进程在 {startup_timeout:g}s 内未通过 /healthz 检查",
        f"查看日志：{log_path}\n{_tail(log_path)}",
    )


def _kill(pid: int, timeout: float) -> bool:
    if not _pid_alive(pid):
        return True
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    deadline = time.monotonic() + max(0.1, timeout)
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.05)
    return not _pid_alive(pid)


def stop_daemon(
    pid_file: str | Path | None = None,
    *,
    timeout: float = DEFAULT_STOP_TIMEOUT,
) -> dict[str, Any]:
    """停止后台服务；PID 文件不存在视为已停止（幂等）。"""
    pid_path, _ = resolve_paths(pid_file)
    state = read_state(pid_path)
    if state is None:
        return {"ok": True, "stopped": False, "reason": "not_running", "pid_file": str(pid_path)}

    pid = int(state["pid"])
    if not _pid_alive(pid):
        pid_path.unlink(missing_ok=True)
        return {"ok": True, "stopped": False, "reason": "stale_pid_file", "pid": pid, "pid_file": str(pid_path)}
    if not _pid_matches(pid):
        raise ConfigError(
            f"PID {pid} 不是 linux-cmd-mcp 进程，拒绝发送信号",
            f"检查 {pid_path} 是否被其他程序复用；确认后可手动删除该状态文件。",
        )

    killed = _kill(pid, timeout)
    pid_path.unlink(missing_ok=True)
    if not killed:
        raise ConfigError(
            f"进程 {pid} 在 {timeout:g}s 内未退出",
            "可用 kill -9 手动处理，并检查是否有子进程占用。",
        )
    return {"ok": True, "stopped": True, "pid": pid, "pid_file": str(pid_path)}


def daemon_status(pid_file: str | Path | None = None) -> dict[str, Any]:
    """返回运行状态；不修改任何文件。"""
    pid_path, _ = resolve_paths(pid_file)
    state = read_state(pid_path)
    if state is None:
        return {"running": False, "reason": "no_pid_file", "pid_file": str(pid_path)}

    pid = int(state["pid"])
    alive = _pid_alive(pid)
    matches = _pid_matches(pid)
    payload: dict[str, Any] = {
        "running": bool(alive and matches),
        "pid": pid,
        "host": state.get("host"),
        "port": state.get("port"),
        "transport": state.get("transport"),
        "log_file": state.get("log_file"),
        "started_at": state.get("started_at"),
        "pid_file": str(pid_path),
    }
    if alive and not matches:
        payload["stale"] = True
        payload["reason"] = "pid_not_matching"
        return payload
    if not alive:
        payload["stale"] = True
        payload["reason"] = "process_not_found"
        return payload

    host = str(state.get("host", "127.0.0.1"))
    port = int(state.get("port", 8765))
    health = probe_health(host, port)
    payload["health"] = health
    payload["healthy"] = bool(health and health.get("status") == "ok")
    return payload
