"""HTTP/SSE 传输层测试：鉴权、Origin 校验、健康探针、非回环 fail-closed、端到端脚本。"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from linux_cmd_mcp.config import Settings
from linux_cmd_mcp.errors import ConfigError
from linux_cmd_mcp.http_transport import (
    BearerAuthMiddleware,
    OriginGuardMiddleware,
    build_http_app,
    serve_http,
)
from linux_cmd_mcp.server import build_server

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TOKEN = "test-token-0123456789abcdef"


class _EchoApp:
    """最小 ASGI 应用：任何放行的请求都回 200 ok。"""

    async def __call__(self, scope, receive, send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"ok"})


def _client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1")


def test_bearer_middleware_rejects_missing_and_wrong_token() -> None:
    async def scenario() -> None:
        app = BearerAuthMiddleware(_EchoApp(), token=TOKEN)
        async with _client(app) as client:
            missing = await client.get("/sse")
            assert missing.status_code == 401
            assert missing.json()["error"] == "unauthorized"
            assert missing.headers["www-authenticate"].startswith("Bearer")

            wrong = await client.get("/sse", headers={"Authorization": "Bearer nope"})
            assert wrong.status_code == 401

            ok = await client.get("/sse", headers={"Authorization": f"Bearer {TOKEN}"})
            assert ok.status_code == 200

            health = await client.get("/healthz")
            assert health.status_code == 200  # 探针免鉴权

    asyncio.run(scenario())


def test_bearer_middleware_is_disabled_without_token() -> None:
    async def scenario() -> None:
        async with _client(BearerAuthMiddleware(_EchoApp(), token=None)) as client:
            assert (await client.get("/mcp")).status_code == 200

    asyncio.run(scenario())


def test_origin_guard_allows_loopback_and_rejects_foreign_origin() -> None:
    async def scenario() -> None:
        app = OriginGuardMiddleware(_EchoApp(), allowed_origins=())
        async with _client(app) as client:
            assert (await client.get("/sse", headers={"Origin": "http://127.0.0.1:3000"})).status_code == 200
            assert (await client.get("/sse", headers={"Origin": "http://localhost:5173"})).status_code == 200
            assert (await client.get("/sse")).status_code == 200  # 无 Origin 的非浏览器客户端
            rejected = await client.get("/sse", headers={"Origin": "http://evil.example.com"})
            assert rejected.status_code == 403
            assert rejected.json()["error"] == "origin_not_allowed"

        allowlisted = OriginGuardMiddleware(_EchoApp(), allowed_origins=("https://ops.example.com",))
        async with _client(allowlisted) as client:
            assert (
                await client.get("/sse", headers={"Origin": "https://ops.example.com/"})
            ).status_code == 200

    asyncio.run(scenario())


@pytest.mark.parametrize("transport", ["sse", "streamable-http"])
def test_build_http_app_exposes_healthz_and_keeps_sdk_routes(transport: str) -> None:
    settings = Settings.from_env({"LCMD_AUTH_TOKEN": TOKEN})
    mcp = build_server(settings)
    app = build_http_app(mcp, settings, transport)
    paths = [getattr(route, "path", "") for route in app.routes]
    assert "/healthz" in paths

    async def scenario() -> None:
        async with _client(app) as client:
            health = await client.get("/healthz")
            assert health.status_code == 200
            payload = health.json()
            assert payload["transport"] == transport
            assert payload["auth_enabled"] is True
            # 健康探针不得泄露命令信息或令牌
            dumped = json.dumps(payload)
            assert "token" not in dumped.lower()
            assert "commands" not in payload

            unauthorized = await client.get("/sse" if transport == "sse" else "/mcp")
            assert unauthorized.status_code == 401

    asyncio.run(scenario())


def test_serve_http_fails_closed_on_non_loopback_without_token() -> None:
    settings = Settings.from_env({})
    mcp = build_server(settings)
    with pytest.raises(ConfigError) as exc:
        serve_http(mcp, settings, "sse", host="0.0.0.0", port=9000)
    assert "LCMD_AUTH_TOKEN" in str(exc.value)


def test_serve_http_allows_non_loopback_with_token(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings.from_env({"LCMD_AUTH_TOKEN": TOKEN})
    mcp = build_server(settings)
    started: dict[str, object] = {}

    def fake_run(app, **kwargs):
        started.update(kwargs)
        started["app"] = app

    import uvicorn

    monkeypatch.setattr(uvicorn, "run", fake_run)
    serve_http(mcp, settings, "streamable-http", host="0.0.0.0", port=9100)
    assert started["host"] == "0.0.0.0"
    assert started["port"] == 9100
    assert started["access_log"] is False


def test_http_transport_end_to_end_script() -> None:
    """真起服务器进程：SSE 与 Streamable HTTP 各跑一遍握手 + 401 + 403 + 策略拒绝。"""
    proc = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "check_http_transport.py")],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        timeout=240,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "共 20 项" in proc.stdout


def test_bearer_scheme_is_case_insensitive() -> None:
    """RFC 7235：认证 scheme 不区分大小写，bearer 也要能通过。"""
    async def scenario() -> None:
        async with _client(BearerAuthMiddleware(_EchoApp(), token=TOKEN)) as client:
            lower = await client.get("/sse", headers={"Authorization": f"bearer {TOKEN}"})
            assert lower.status_code == 200
            mixed = await client.get("/sse", headers={"Authorization": f"BeArEr {TOKEN}"})
            assert mixed.status_code == 200

    asyncio.run(scenario())


def test_origin_guard_rejects_userinfo_disguise_and_accepts_ipv6_loopback() -> None:
    async def scenario() -> None:
        app = OriginGuardMiddleware(_EchoApp(), allowed_origins=())
        async with _client(app) as client:
            disguised = await client.get(
                "/sse", headers={"Origin": "http://127.0.0.1:9999@evil.example.com"}
            )
            assert disguised.status_code == 403
            ipv6 = await client.get("/sse", headers={"Origin": "http://[::1]:8765"})
            assert ipv6.status_code == 200
            null_origin = await client.get("/sse", headers={"Origin": "null"})
            assert null_origin.status_code == 403

    asyncio.run(scenario())
