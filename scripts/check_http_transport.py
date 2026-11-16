#!/usr/bin/env python3
"""SSE 与 Streamable HTTP 传输的真实端到端自检。

做四件事（缺一不可）：

1. **鉴权**：不带 ``Authorization: Bearer`` 的请求必须 401；带正确令牌才可用。
2. **Origin 校验**：伪造 ``Origin: http://evil.example`` 必须 403（防 DNS rebinding）。
3. **SSE 握手**：用官方 SDK 的 ``sse_client`` 完成 initialize → tools/list →
   tools/call（含策略拒绝路径）。
4. **Streamable HTTP 握手**：同上，走单端点 ``/mcp``。

用法::

    python3 scripts/check_http_transport.py --verbose

退出码 0 表示全部通过；1 表示失败（会打印服务器 stderr 与失败断言）。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamablehttp_client

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_TOOLS = {
    "list_commands",
    "describe_command",
    "execute_command",
    "check_command",
    "get_system_info",
    "validate_working_directory",
}


class CheckFailure(Exception):
    pass


def pass_line(message: str) -> None:
    print(f"PASS: {message}")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def http_json(url: str, headers: dict[str, str] | None = None, timeout: float = 5.0) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {"raw": body}
        return exc.code, payload


def start_server(transport: str, port: int, token: str, workdir: str, policy_mode: str) -> tuple[subprocess.Popen[str], Path]:
    stderr_path = Path(tempfile.mkstemp(prefix=f"lcmd-{transport}-", suffix=".log")[1])
    handle = stderr_path.open("w", encoding="utf-8")
    env = dict(os.environ)
    env.update(
        {
            "PYTHONUNBUFFERED": "1",
            "LCMD_AUTH_TOKEN": token,
            "LCMD_POLICY_MODE": policy_mode,
            "LCMD_ALLOWED_WORKDIRS": workdir,
            "LCMD_LOG_LEVEL": "INFO",
            "LCMD_DISCOVERY_TTL_SECONDS": "0",
        }
    )
    src = PROJECT_ROOT / "src"
    if src.is_dir():
        env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(src), env.get("PYTHONPATH", "")]))
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "linux_cmd_mcp",
            "--transport",
            transport,
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=handle,
        text=True,
        env=env,
        cwd=str(PROJECT_ROOT),
    )
    return proc, stderr_path


def wait_ready(port: int, timeout: float = 20.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    url = f"http://127.0.0.1:{port}/healthz"
    while time.monotonic() < deadline:
        try:
            status, payload = http_json(url, timeout=1.0)
            if status == 200:
                return payload
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            pass
        time.sleep(0.2)
    raise CheckFailure(f"服务器在 {timeout}s 内未就绪（{url}）")


async def exercise(transport: str, port: int, token: str, workdir: str) -> int:
    checks = 0
    headers = {"Authorization": f"Bearer {token}"}
    if transport == "sse":
        url = f"http://127.0.0.1:{port}/sse"
        async with sse_client(url, headers=headers) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                checks += await run_session(session, transport, workdir)
    else:
        url = f"http://127.0.0.1:{port}/mcp"
        async with streamablehttp_client(url, headers=headers) as (read_stream, write_stream, _get_session_id):
            async with ClientSession(read_stream, write_stream) as session:
                checks += await run_session(session, transport, workdir)
    return checks


async def run_session(session: ClientSession, transport: str, workdir: str) -> int:
    checks = 0
    info = await session.initialize()
    if info.serverInfo.name != "linux_cmd_mcp":
        raise CheckFailure(f"serverInfo.name 不符：{info.serverInfo}")
    if "tools" not in (info.capabilities.model_dump(exclude_none=True) if hasattr(info.capabilities, "model_dump") else {}):
        pass  # capabilities 结构随 SDK 版本变化，工具可用性由 tools/list 验证
    pass_line(f"[{transport}] initialize（serverInfo={info.serverInfo.name} {info.serverInfo.version}）")
    checks += 1

    tools = await session.list_tools()
    names = {tool.name for tool in tools.tools}
    if names != EXPECTED_TOOLS:
        raise CheckFailure(f"[{transport}] 工具集合不符：{sorted(names)}")
    exec_tool = next(tool for tool in tools.tools if tool.name == "execute_command")
    if "params" in ((exec_tool.inputSchema or {}).get("properties") or {}):
        raise CheckFailure(f"[{transport}] inputSchema 仍是嵌套 params")
    if not exec_tool.outputSchema:
        raise CheckFailure(f"[{transport}] execute_command 缺少 outputSchema")
    pass_line(f"[{transport}] tools/list（{len(tools.tools)} 个工具，扁平 schema + outputSchema）")
    checks += 1

    listing = await session.call_tool("list_commands", {"limit": 5})
    payload = listing.structuredContent or {}
    if not payload.get("commands"):
        raise CheckFailure(f"[{transport}] list_commands 未返回候选：{listing}")
    pass_line(f"[{transport}] tools/call list_commands（total_matched={payload.get('total_matched')}）")
    checks += 1

    check_result = await session.call_tool("check_command", {"command": "ls"})
    check_payload = check_result.structuredContent or {}
    if not (check_payload.get("exists") and check_payload.get("executable")):
        raise CheckFailure(f"[{transport}] check_command 结果不符：{check_payload}")
    pass_line(f"[{transport}] tools/call check_command（resolved_path={(check_result.structuredContent or {}).get('resolved_path')}）")
    checks += 1

    run_result = await session.call_tool(
        "execute_command", {"command": "echo", "args": ["hello-sse"], "cwd": workdir}
    )
    if run_result.isError:
        raise CheckFailure(f"[{transport}] execute_command 失败：{run_result.content}")
    if (run_result.structuredContent or {}).get("stdout") != "hello-sse\n":
        raise CheckFailure(f"[{transport}] execute_command 输出不符：{run_result.structuredContent}")
    pass_line(f"[{transport}] tools/call execute_command（exit_code=0，真实执行）")
    checks += 1

    denied = await session.call_tool("execute_command", {"command": "rm", "args": ["-rf", workdir]})
    if not denied.isError or "POLICY_DENIED" not in text_of(denied):
        raise CheckFailure(f"[{transport}] rm 未被策略拒绝：{denied}")
    pass_line(f"[{transport}] 策略拒绝 over {transport}（POLICY_DENIED）")
    checks += 1
    return checks


def text_of(result: Any) -> str:
    return "\n".join(item.text for item in result.content if getattr(item, "type", "") == "text")


def run_transport(transport: str, *, verbose: bool) -> int:
    port = free_port()
    workdir = tempfile.mkdtemp(prefix="lcmd-http-")
    token = "lcmd-" + secrets.token_hex(16)
    proc, stderr_path = start_server(transport, port, token, workdir, policy_mode="standard")
    base = f"http://127.0.0.1:{port}"
    checks = 0
    try:
        health = wait_ready(port)
        if health.get("transport") != transport or health.get("auth_enabled") is not True:
            raise CheckFailure(f"/healthz 内容不符：{health}")
        pass_line(f"[{transport}] /healthz 就绪（鉴权=开，policy={health.get('policy_mode')}）")
        checks += 1

        status, payload = http_json(f"{base}/healthz")
        if status != 200:
            raise CheckFailure("健康检查需要免鉴权")
        checks += 1

        probe_path = "/sse" if transport == "sse" else "/mcp"
        request = urllib.request.Request(f"{base}{probe_path}", headers={"Accept": "text/event-stream"})
        try:
            urllib.request.urlopen(request, timeout=3)
            raise CheckFailure("无令牌请求竟然成功")
        except urllib.error.HTTPError as exc:
            if exc.code != 401:
                raise CheckFailure(f"无令牌请求应 401，实际 {exc.code}")
            body = json.loads(exc.read().decode("utf-8"))
            if body.get("error") != "unauthorized":
                raise CheckFailure(f"401 负载不符：{body}")
        pass_line(f"[{transport}] 无令牌 {probe_path} → 401 unauthorized")
        checks += 1

        request = urllib.request.Request(
            f"{base}{probe_path}",
            headers={"Accept": "text/event-stream", "Origin": "http://evil.example.com"},
        )
        try:
            urllib.request.urlopen(request, timeout=3)
            raise CheckFailure("非法 Origin 请求竟然成功")
        except urllib.error.HTTPError as exc:
            if exc.code != 403:
                raise CheckFailure(f"非法 Origin 应 403，实际 {exc.code}")
        pass_line(f"[{transport}] 非法 Origin → 403 origin_not_allowed")
        checks += 1

        checks += asyncio.run(exercise(transport, port, token, workdir))
        if verbose:
            print(f"-- transport={transport} port={port} checks={checks}")
        return checks
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
        stderr_path.unlink(missing_ok=True)
        if proc.returncode not in (0, -15, 143, None):
            raise CheckFailure(f"{transport} 服务器退出码异常：{proc.returncode}\nstderr:\n{stderr_text[-3000:]}")
        if verbose and stderr_text:
            print(f"-- [{transport}] 服务器 stderr 摘要：{stderr_text.strip().splitlines()[-1] if stderr_text.strip() else '(空)'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="linux-cmd-mcp 的 SSE / Streamable HTTP 自检")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--transport", choices=["sse", "streamable-http", "all"], default="all")
    args = parser.parse_args(argv)

    transports = ["sse", "streamable-http"] if args.transport == "all" else [args.transport]
    total = 0
    try:
        for transport in transports:
            total += run_transport(transport, verbose=args.verbose)
    except CheckFailure as exc:
        print(f"FAIL: {exc}")
        return 1
    print(f"\nHTTP 传输自检通过，共 {total} 项。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
