#!/usr/bin/env python3
"""稳定性压测：并发、非法入参风暴、超时回收、长跑内存、优雅退出。

用法:
    python3 scripts/check_stability.py                 # 默认：并发 8、压测 100 次、长跑 60s
    python3 scripts/check_stability.py --soak 120 --clients 12

设计原则：
* 全部通过真实 SSE + Bearer 会话，与生产一致；
* 每个断言都带可复现的输入；
* 退出码 0 = 全部通过；1 = 有失败。
"""

from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx
from mcp import ClientSession
from mcp.client.sse import sse_client

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class Runner:
    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[str] = []
        self.notes: list[str] = []

    def check(self, condition: bool, title: str) -> None:
        if condition:
            self.passed += 1
            print(f"PASS: {title}")
        else:
            self.failed.append(title)
            print(f"FAIL: {title}")

    def note(self, text: str) -> None:
        self.notes.append(text)
        print(f"NOTE: {text}")

    def summary(self) -> int:
        total = self.passed + len(self.failed)
        print()
        if self.failed:
            print(f"FAILED {len(self.failed)}/{total}:")
            for item in self.failed:
                print("  -", item)
            return 1
        print(f"合计：PASS {total} 项，FAIL 0 项")
        print("稳定性压测全部通过。")
        return 0


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def rss_kb(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except OSError:
        pass
    return 0


def structured(result: Any) -> dict[str, Any]:
    data = getattr(result, "structuredContent", None)
    if data is None:
        text = result.content[0].text if result.content else ""
        raise AssertionError(f"没有 structuredContent：{text[:160]}")
    return data


async def call(session: ClientSession, name: str, arguments: dict[str, Any] | None = None):
    return await session.call_tool(name, arguments or {})


async def one_client(port: int, token: str, runner: Runner, client_id: int, rounds: int) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    async with sse_client(f"http://127.0.0.1:{port}/sse", headers=headers) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for i in range(rounds):
                out = structured(
                    await call(session, "execute_command",
                               {"command": "echo", "args": [f"client{client_id}-{i}"], "cwd": "/tmp"})
                )
                if out["exit_code"] != 0 or out["stdout"].strip() != f"client{client_id}-{i}":
                    runner.check(False, f"并发客户端 {client_id} 第 {i} 次结果正确")
                    return
                listing = structured(await call(session, "list_commands", {"limit": 3}))
                if len(listing["commands"]) != 3:
                    runner.check(False, f"并发客户端 {client_id} list_commands 正常")
                    return
    runner.check(True, f"并发客户端 {client_id} 完成 {rounds} 轮（命令行 + 列表）")


async def drive(port: int, token: str, runner: Runner, args, server: subprocess.Popen, log_path: str) -> None:
    headers = {"Authorization": f"Bearer {token}"}

    # ---------- 1. 顺序重复调用（稳定复现） ----------
    async with sse_client(f"http://127.0.0.1:{port}/sse", headers=headers) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for cycle in range(3):
                ok = True
                for name, payload in [
                    ("get_system_info", {}),
                    ("check_command", {"command": "ls"}),
                    ("describe_command", {"command": "ls"}),
                    ("validate_working_directory", {"path": "/tmp"}),
                    ("list_commands", {"limit": 5}),
                ]:
                    result = await call(session, name, payload)
                    ok = ok and not result.isError and result.structuredContent is not None
                runner.check(ok, f"顺序调用 6 个工具第 {cycle + 1} 轮全部正常")

    # ---------- 2. 并发 ----------
    base = rss_kb(server.pid)
    await asyncio.gather(*(one_client(port, token, runner, i, 10) for i in range(1, args.clients + 1)))
    after = rss_kb(server.pid)
    runner.check(after - base < 60_000, f"并发后常驻内存增长 < 60MB（{base} -> {after} KB）")

    # ---------- 3. 非法入参风暴 ----------
    bad = 0
    async with sse_client(f"http://127.0.0.1:{port}/sse", headers=headers) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for i in range(args.storm):
                result = await call(session, "list_commands", {"limit": 0, "offset": i})
                if result.isError and "INVALID_ARGUMENT" in (result.content[0].text if result.content else ""):
                    bad += 1
            alive = structured(await call(session, "execute_command", {"command": "echo", "args": ["alive"]}))
    runner.check(bad == args.storm, f"非法入参风暴 {args.storm} 次全部结构化拒绝（实际 {bad}）")
    runner.check(alive["stdout"].strip() == "alive", "风暴后服务器仍可正常执行命令")

    # ---------- 4. 超时回收 ----------
    async with sse_client(f"http://127.0.0.1:{port}/sse", headers=headers) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for i in range(3):
                out = structured(
                    await call(session, "execute_command",
                               {"command": "sleep", "args": ["31"], "timeout_seconds": 1, "cwd": "/tmp"})
                )
                runner.check(out["timed_out"] is True, f"第 {i + 1} 次超时标记 timed_out=True")
            gone = False
            for _ in range(10):
                await asyncio.sleep(0.4)
                probe = structured(await call(session, "execute_command",
                                              {"command": "pgrep", "args": ["-a", "-f", "^sleep 31$"]}))
                if probe["exit_code"] != 0:
                    gone = True
                    break
            runner.check(gone, "多次超时后无残留 sleep 进程")

    # ---------- 5. 长跑 + 内存 ----------
    start_rss = rss_kb(server.pid)
    started = time.monotonic()
    calls = 0
    samples: list[int] = []
    async with sse_client(f"http://127.0.0.1:{port}/sse", headers=headers) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            while time.monotonic() - started < args.soak:
                out = structured(
                    await call(session, "execute_command", {"command": "true", "cwd": "/tmp"})
                )
                calls += 1
                if out["exit_code"] != 0:
                    runner.check(False, "长跑中出现非 0 退出")
                    break
                if calls % 50 == 0:
                    samples.append(rss_kb(server.pid))
    peak = max([start_rss, *samples]) if samples else start_rss
    runner.check(peak - start_rss < 40_000,
                 f"长跑 {args.soak}s / {calls} 次调用内存稳定（{start_rss} -> {peak} KB）")
    runner.check(calls > 0, f"长跑实际完成 {calls} 次调用")

    # ---------- 6. 优雅退出 ----------
    server.terminate()
    try:
        server.wait(timeout=15)
    except subprocess.TimeoutExpired:
        server.kill()
        runner.check(False, "SIGTERM 后 15s 内未退出")
        return
    stderr = Path(log_path).read_text(encoding="utf-8", errors="replace")
    runner.check("Traceback" not in stderr, "SIGTERM 退出无 traceback")
    runner.check(sum(1 for line in stderr.splitlines() if " ERROR " in line) == 0, "SIGTERM 退出日志无 ERROR")


def wait_ready(port: int, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            response = httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=1.0)
            if response.status_code == 200:
                return True
        except httpx.HTTPError:
            time.sleep(0.2)
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--soak", type=int, default=60, help="长跑秒数（默认 60）")
    parser.add_argument("--clients", type=int, default=8, help="并发客户端数（默认 8）")
    parser.add_argument("--storm", type=int, default=100, help="非法入参次数（默认 100）")
    parsed = parser.parse_args()

    port, token = free_port(), secrets.token_hex(16)
    env = dict(os.environ)
    env.update({
        "LCMD_POLICY_MODE": "unrestricted",
        "LCMD_AUTH_TOKEN": token,
        "LCMD_ALLOWED_WORKDIRS": "/tmp,/home/user",
        "LCMD_LOG_LEVEL": "INFO",
        "LCMD_DISCOVERY_TTL_SECONDS": "0",
    })
    # stderr 必须落盘而不是接 PIPE：无人读取的管道写满 64KB 会阻塞服务器写日志，
    # 进而让 SSE 停止输出、客户端误报 httpx.ReadTimeout（已实测确认的坑）。
    stderr_file = tempfile.NamedTemporaryFile(prefix="lcmd-stability-", suffix=".log", delete=False)
    server = subprocess.Popen(
        [sys.executable, "-m", "linux_cmd_mcp", "--transport", "sse", "--host", "127.0.0.1", "--port", str(port)],
        env=env, stdout=subprocess.DEVNULL, stderr=stderr_file, cwd=str(PROJECT_ROOT),
    )
    if not wait_ready(port):
        server.kill()
        print("FAIL: 服务器未在 30s 内就绪")
        return 1

    runner = Runner()
    try:
        asyncio.run(drive(port, token, runner, parsed, server, stderr_file.name))
    finally:
        if server.poll() is None:
            server.kill()
    return runner.summary()


if __name__ == "__main__":
    raise SystemExit(main())
