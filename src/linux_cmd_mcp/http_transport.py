"""SSE 与 Streamable HTTP 传输：ASGI 装配、Bearer 鉴权、Origin 校验。

两种传输都来自官方 SDK（``FastMCP.sse_app()`` / ``streamable_http_app()``），
本模块只做“包一层”，不手搓任何 JSON-RPC 帧：

* **SSE**（``--transport sse``）：``GET /sse`` 建立事件流，``POST /messages/`` 上行。
  这是 MCP 最早的 HTTP 传输，兼容性最好，适合“像 SSH 服务器一样常驻”的用法。
* **Streamable HTTP**（``--transport streamable-http``）：单端点 ``/mcp``，
  支持会话续传，是新版规范推荐的远程传输。

安全边界（缺一不可）：

1. 监听非回环地址时**必须**配置 ``LCMD_AUTH_TOKEN``，否则启动即失败（fail closed）。
2. 配置了令牌时，除 ``/healthz`` 外所有请求都要带 ``Authorization: Bearer <token>``，
   比较用 ``hmac.compare_digest``（固定时间，避免时序侧信道）。
3. 带 ``Origin`` 头的请求（浏览器/代理场景）只允许 ``LCMD_ALLOWED_ORIGINS`` 或回环
   来源，防 DNS rebinding；非浏览器客户端通常不带 ``Origin``，正常放行。
"""

from __future__ import annotations

import hmac
import json
import logging
from typing import Any
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import Settings
from .errors import ConfigError

logger = logging.getLogger("linux_cmd_mcp")

LOOPBACK_ORIGIN_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
LOOPBACK_BIND_HOSTS = {"127.0.0.1", "localhost", "::1"}
HEALTH_PATH = "/healthz"


async def _respond_json(
    send: Send,
    status: int,
    payload: dict[str, Any],
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = [
        (b"content-type", b"application/json; charset=utf-8"),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"cache-control", b"no-store"),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def _lower_headers(scope: Scope) -> dict[str, str]:
    return {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope.get("headers", [])}


class _GuardMiddleware:
    """纯 ASGI 中间件基类：``_guard`` 返回 False 表示已就地返回响应。"""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def _guard(self, scope: Scope, send: Send) -> bool:  # pragma: no cover - 子类实现
        raise NotImplementedError

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if await self._guard(scope, send):
            await self.app(scope, receive, send)


class BearerAuthMiddleware(_GuardMiddleware):
    """除健康检查外，所有请求都要求 Bearer 令牌（令牌未配置时不启用）。"""

    def __init__(self, app: ASGIApp, token: str | None) -> None:
        super().__init__(app)
        self.token = token

    async def _guard(self, scope: Scope, send: Send) -> bool:
        if not self.token or scope["path"].rstrip("/") == HEALTH_PATH:
            return True
        provided = _lower_headers(scope).get("authorization", "")
        # RFC 7235 规定认证 scheme 大小写不敏感：Bearer / bearer 都接受，
        # 令牌本身仍用固定时间比较。
        scheme, _, credentials = provided.partition(" ")
        if scheme.lower() == "bearer" and hmac.compare_digest(credentials.strip(), self.token):
            logger.debug("authorized %s %s", scope.get("method"), scope.get("path"))
            return True
        await _respond_json(
            send,
            401,
            {"error": "unauthorized", "detail": "需要 Authorization: Bearer <LCMD_AUTH_TOKEN>"},
            [(b"www-authenticate", b'Bearer realm="linux-cmd-mcp"')],
        )
        return False


class OriginGuardMiddleware(_GuardMiddleware):
    """带 Origin 头的请求只允许配置的来源或回环来源（防 DNS rebinding）。"""

    def __init__(self, app: ASGIApp, allowed_origins: tuple[str, ...] = ()) -> None:
        super().__init__(app)
        self.allowed = frozenset(origin.rstrip("/") for origin in allowed_origins)

    @staticmethod
    def _origin_host(origin: str) -> str | None:
        """取 Origin 的主机名；带 userinfo、解析失败或非标准来源一律返回 None。"""
        try:
            parsed = urlsplit(origin)
        except ValueError:
            return None
        if parsed.username is not None or parsed.password is not None:
            # 浏览器不会在 Origin 里发 userinfo；出现即视为伪装（例如
            # http://127.0.0.1:9999@evil.com 想借主机名匹配绕过）。
            return None
        return parsed.hostname

    def _is_allowed(self, origin: str) -> bool:
        normalized = origin.rstrip("/")
        if normalized in self.allowed:
            return True
        host = self._origin_host(normalized)
        return host is not None and host in LOOPBACK_ORIGIN_HOSTS

    async def _guard(self, scope: Scope, send: Send) -> bool:
        origin = _lower_headers(scope).get("origin")
        if origin is None:
            return True  # 非浏览器客户端不带 Origin
        if self._is_allowed(origin):
            return True
        await _respond_json(
            send, 403, {"error": "origin_not_allowed", "detail": f"Origin {origin} 不在允许列表内"}
        )
        return False


def build_http_app(mcp: FastMCP, settings: Settings, transport: str) -> Starlette:
    """构造带鉴权与 Origin 校验的 ASGI 应用。"""
    if transport == "sse":
        app = mcp.sse_app()
    elif transport == "streamable-http":
        app = mcp.streamable_http_app()
    else:  # pragma: no cover - CLI 已限制取值
        raise ConfigError(f"不支持的传输：{transport}", "可选 stdio / sse / streamable-http")

    # Starlette 里“最后 add 的中间件在最外层”：先装鉴权、再装 Origin 校验，
    # 让恶意 Origin 在消耗鉴权校验之前就被 403 拦掉（防御顺序有语义）。
    app.add_middleware(BearerAuthMiddleware, token=settings.auth_token)
    app.add_middleware(OriginGuardMiddleware, allowed_origins=settings.allowed_origins)

    async def healthz(_request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "transport": transport,
                "auth_enabled": settings.auth_token is not None,
                "policy_mode": settings.policy_mode,
            }
        )

    # /healthz 挂在路由最前面：探针不应受鉴权影响，也不泄露任何命令信息。
    app.router.routes.insert(0, Route(HEALTH_PATH, endpoint=healthz, methods=["GET"]))
    return app


def serve_http(mcp: FastMCP, settings: Settings, transport: str, *, host: str, port: int) -> None:
    """用 uvicorn 常驻 SSE / Streamable HTTP 服务。"""
    if transport not in {"sse", "streamable-http"}:
        raise ConfigError(f"不支持的 HTTP 传输：{transport}", "可选 sse / streamable-http")

    if host not in LOOPBACK_BIND_HOSTS and settings.auth_token is None:
        raise ConfigError(
            f"拒绝在 {host} 上无鉴权启动：远程可达的命令执行接口必须配 LCMD_AUTH_TOKEN",
            "设置 LCMD_AUTH_TOKEN（至少 16 字符，建议 openssl rand -hex 32），或改绑 127.0.0.1。",
        )

    if settings.policy_mode == "unrestricted":
        logger.warning("policy=unrestricted：任何命令都会放行（等同运行本服务的 Linux 用户权限）")
    if settings.auth_token is None:
        logger.warning("未配置 LCMD_AUTH_TOKEN：仅因绑定 %s 才允许启动，本机任意进程都可调用", host)

    app = build_http_app(mcp, settings, transport)
    import uvicorn

    endpoints = {"sse": "GET /sse + POST /messages/", "streamable-http": "POST/GET /mcp"}
    logger.info(
        "%s 监听 http://%s:%d/ （%s）；鉴权=%s，Origin 校验=开",
        transport,
        host,
        port,
        endpoints[transport],
        "开" if settings.auth_token else "关",
    )
    uvicorn.run(app, host=host, port=port, log_level=settings.log_level.lower(), access_log=False)
