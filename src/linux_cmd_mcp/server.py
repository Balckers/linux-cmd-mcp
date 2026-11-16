"""MCP 服务器装配与 CLI 入口。

传输层：三种，均基于官方 SDK，不手搓帧。

* ``sse``（默认）：``GET /sse`` + ``POST /messages/``，可像 SSH 服务器一样常驻，
  供远程宿主/IDE 连接。
* ``streamable-http``：单端点 ``/mcp``，新版规范推荐的远程传输。
* ``stdio``：本地宿主把服务器当子进程拉起时使用（Claude Desktop 等）。

HTTP/SSE 的鉴权与网络面约束见 :mod:`linux_cmd_mcp.http_transport`：
绑定非回环地址必须有 ``LCMD_AUTH_TOKEN``，全部请求（除 ``/healthz``）校验
``Authorization: Bearer``，带 ``Origin`` 的请求做来源校验。

协议提醒：MCP 的 stdio 传输使用 **逐行 JSON（NDJSON）** 帧，不是 LSP 的
``Content-Length`` 头分帧；因此本项目的握手脚本按行解析，不能用
Content-Length 分帧去校验。
"""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import sys
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager

from mcp import types as mcp_types
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import ValidationError

from . import __version__
from .config import Settings
from .daemon import daemon_status, start_daemon, stop_daemon
from .errors import ConfigError, ErrorCode, ToolFailure
from .http_transport import serve_http
from .logging_setup import configure_logging
from .state import AppState, build_state
from .tools import register_tools
from .tools._common import policy_summary, set_current_state
from .tools._flat import INPUT_MODELS, install_sdk_compat

logger = logging.getLogger("linux_cmd_mcp")

DEFAULT_ALLOWED_HOSTS = ("127.0.0.1:*", "localhost:*", "[::1]:*")
DEFAULT_ALLOWED_ORIGINS = ("http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*")

INSTRUCTIONS = """\
本服务器在本地 Linux 上提供受控、可审计的命令发现与执行能力，共 6 个工具：
list_commands / describe_command / check_command / execute_command /
get_system_info / validate_working_directory。

策略档位（LCMD_POLICY_MODE）：默认 ``unrestricted`` = SSH 级完整控制，
只受 LCMD_DENYLIST 与操作系统权限约束；``permissive`` / ``standard`` / ``strict``
是逐级收紧的护栏档位，需要时可显式切回。

传输：默认 SSE（GET /sse + POST /messages/），也可 ``--transport streamable-http``
（单端点 /mcp）或 ``--transport stdio``（本地宿主子进程）。HTTP/SSE 需在
``Authorization: Bearer <LCMD_AUTH_TOKEN>`` 头里带令牌（未配令牌时仅允许绑回环地址）。

推荐工作流：
1) 不确定命令是否存在或来自哪个目录时，先用 list_commands 或 check_command。
2) 任何有写操作或破坏可能的命令（cp、mv、mkdir、git、tar…）先
   execute_command(dry_run=true)，确认 argv、cwd、env_keys 与 risk 后再真实执行。
3) execute_command 没有 shell，command 与 args 必须分离；管道、重定向、
   通配符请交给目标程序自身的参数，或改用专门的脚本文件。

安全边界：命令执行受三层约束——策略层（硬拒绝/模式/黑白名单）、cwd 允许根目录、
env 白名单，以及 timeout/输出/并发限额。它是护栏而非沙箱：无法阻止
`find -exec`、`python -c` 之类的间接执行，真正的隔离请用专用低权限用户或
容器/cgroups/seccomp。

错误约定：业务失败返回 isError=true，text 为 JSON
`{"ok": false, "error": {"code": "...", "message": "...", "hint": "...", "details": {...}}}`；
客户端可从第一个 `{` 起解析。协议级错误（未知工具、参数解析失败）由 SDK
以 JSON-RPC error 返回。

传输与日志：stdio 模式下 stdout 只承载协议帧，所有日志写 stderr。
"""


def _transport_security(settings: Settings) -> TransportSecuritySettings | None:
    """按 ``LCMD_ALLOWED_HOSTS`` 生成 SDK 的 Host/Origin 校验配置。

    SDK 在监听回环地址时会默认开启 DNS rebinding 保护，只允许
    ``127.0.0.1`` / ``localhost`` / ``[::1]`` 作为 Host。经隧道或反向代理
    暴露时，公网域名不是这三个值，会直接返回 ``421 Invalid Host header``，
    即使 Bearer 令牌正确。这里显式把用户声明的公网 Host 加入白名单；
    ``LCMD_ALLOWED_HOSTS=*`` 则关闭该层校验，但仍保留 Bearer 与 Origin 校验。
    """
    if not settings.allowed_hosts:
        return None
    if "*" in settings.allowed_hosts:
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)
    hosts = list(dict.fromkeys([*DEFAULT_ALLOWED_HOSTS, *settings.allowed_hosts]))
    origins = list(dict.fromkeys([*DEFAULT_ALLOWED_ORIGINS, *settings.allowed_origins]))
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=hosts,
        allowed_origins=origins,
    )


def build_server(settings: Settings | None = None) -> FastMCP:
    """构造 FastMCP 实例：配置日志、构建状态、注册工具与 lifespan。"""
    settings = settings or Settings.from_env()
    configure_logging(settings.log_level)

    state = build_state(settings)
    set_current_state(state)
    summary = policy_summary(state)
    logger.info(
        "linux_cmd_mcp %s ready: mode=%s policy_dirs=%d max_timeout=%ss max_output=%sB",
        __version__,
        settings.policy_mode,
        len(state.allowed_command_dirs),
        summary.max_timeout_seconds,
        summary.max_output_bytes,
    )

    @asynccontextmanager
    async def lifespan(_server: FastMCP) -> AsyncIterator[AppState]:
        logger.info("MCP session started")
        try:
            yield state
        finally:
            logger.info("MCP session closed")

    mcp: FastMCP = FastMCP(
        name="linux_cmd_mcp",
        instructions=INSTRUCTIONS,
        lifespan=lifespan,
        log_level=settings.log_level,
        host=settings.http_host,
        transport_security=_transport_security(settings),
    )
    # FastMCP 1.x 未暴露 version 参数，serverInfo.version 取自底层 Server，
    # 这里显式设置，避免宿主把 SDK 版本当成我们的服务版本。
    mcp._mcp_server.version = __version__
    install_sdk_compat()
    register_tools(mcp, state)
    install_argument_guard(mcp)
    return mcp


def install_argument_guard(mcp: FastMCP) -> None:
    """在协议边界先按入参模型校验一次，让“参数非法”也返回结构化 INVALID_ARGUMENT。

    FastMCP 的参数校验失败会抛出 pydantic 的英文文本（``1 validation error for
    ...``），与本项目“业务错误一律 ``isError`` + JSON 负载”的约定不一致；
    ``extra=forbid`` 的多余字段也会被 SDK 的契约模型直接忽略。这里在
    ``CallToolRequest`` 处理器外面包一层：模型校验通过才继续交给 SDK，
    失败则原样返回 ``{"ok": false, "error": {...}}``。
    """
    handler = mcp._mcp_server.request_handlers.get(mcp_types.CallToolRequest)
    if handler is None:  # SDK 结构变了就大声失败，不静默降级
        raise ConfigError(
            "无法安装参数守卫：SDK 未注册 CallToolRequest 处理器。",
            hint="检查 mcp 版本是否仍为 1.30.x（pyproject 已钉死），或调整 install_argument_guard。",
        )

    async def guarded(req: mcp_types.CallToolRequest) -> mcp_types.ServerResult:
        name = req.params.name
        model = INPUT_MODELS.get(name)
        if model is not None:
            arguments = req.params.arguments or {}
            try:
                model.model_validate(arguments)
            except ValidationError as exc:
                fields = []
                for item in exc.errors()[:5]:
                    fields.append(
                        {
                            "field": ".".join(str(part) for part in item.get("loc", ())) or "(body)",
                            "error": str(item.get("msg", "")),
                            "type": str(item.get("type", "")),
                        }
                    )
                detail = "；".join(f"{item['field']} {item['error']}" for item in fields)
                failure = ToolFailure(
                    ErrorCode.INVALID_ARGUMENT,
                    f"参数校验失败：{detail}"[:300],
                    "按该工具的 inputSchema 修正参数类型与取值范围；多余字段会被拒绝。",
                    {"tool": name, "fields": fields},
                )
                logger.info("argument guard rejected %s: %s", name, detail)
                return mcp_types.ServerResult(
                    mcp_types.CallToolResult(
                        content=[mcp_types.TextContent(type="text", text=failure.to_json())],
                        isError=True,
                    )
                )
        return await handler(req)

    mcp._mcp_server.request_handlers[mcp_types.CallToolRequest] = guarded  # type: ignore[assignment]
    logger.debug("CallToolRequest 参数守卫已安装（%d 个工具）", len(INPUT_MODELS))


def describe_configuration(settings: Settings, transport: str = "sse") -> dict[str, object]:
    """``--check-config`` 的诊断输出（不含任何密钥/环境变量值）。"""
    state = build_state(settings)
    snapshot = state.discovery.snapshot(refresh=True)
    return {
        "ok": True,
        "version": __version__,
        "transport": transport,
        "http": settings.http_summary(),
        "policy": settings.policy_summary(),
        "path_env": snapshot.path_env,
        "scan_duration_ms": snapshot.scan_duration_ms,
        "command_count": len(snapshot.commands),
        "scanned_dirs": [
            {"index": d.index, "path": d.path, "note": d.note}
            for d in snapshot.dirs
            if d.status == "scanned"
        ],
        "skipped_dirs": [
            {"index": d.index, "path": d.path, "status": d.status, "note": d.note}
            for d in snapshot.dirs
            if d.status != "scanned"
        ],
        "allowed_command_dirs": list(state.allowed_command_dirs),
    }


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="linux-cmd-mcp",
        description="Linux 原生命令 MCP 服务器（SSE / Streamable HTTP / stdio）",
    )
    parser.add_argument(
        "--transport",
        choices=["sse", "streamable-http", "stdio"],
        default="sse",
        help="传输方式：sse（默认，GET /sse + POST /messages/）| streamable-http（单端点 /mcp）| stdio",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="HTTP/SSE 监听地址（修改绑定 IP），默认取 LCMD_HTTP_HOST（127.0.0.1）",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="HTTP/SSE 监听端口，默认取 LCMD_HTTP_PORT（8765）",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="打印生效配置与 PATH 扫描摘要后退出（不启动 MCP 会话）",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--daemon",
        "--background",
        dest="daemon",
        action="store_true",
        help="后台启动并等待 /healthz 就绪；SSE / Streamable HTTP 可用，stdio 不支持",
    )
    mode.add_argument(
        "--stop",
        action="store_true",
        help="按 PID 文件停止后台实例（幂等）",
    )
    mode.add_argument(
        "--status",
        action="store_true",
        help="查看后台实例状态（运行中返回 0，未运行返回 1）",
    )
    parser.add_argument(
        "--pid-file",
        default=None,
        help="PID 状态文件；默认 $XDG_STATE_HOME/linux-cmd-mcp/server.pid 或 ~/.local/state/linux-cmd-mcp/server.pid",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="后台日志文件；默认与 PID 文件同目录的 server.log",
    )
    parser.add_argument(
        "--startup-timeout",
        type=float,
        default=8.0,
        help="--daemon 等待 /healthz 就绪的秒数（默认 8）",
    )
    parser.add_argument(
        "--stop-timeout",
        type=float,
        default=10.0,
        help="--stop 等待进程退出的秒数（默认 10，超时发 SIGKILL）",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        help="覆盖 LCMD_LOG_LEVEL，用于临时排查",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"linux-cmd-mcp {__version__}",
    )
    return parser.parse_args(argv)


def _normalize_host(host: str) -> str:
    value = host.strip()
    if not value or any(ch.isspace() for ch in value):
        raise ConfigError(f"监听地址 {host!r} 非法", "写 IP 或主机名，例如 127.0.0.1、0.0.0.0、192.168.1.20")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    return value


def _print_json(payload: object) -> None:
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)

    # 停止/状态不依赖业务配置：即使环境变量坏掉，也要能把后台实例收回来。
    if args.status:
        try:
            payload = daemon_status(args.pid_file)
        except ConfigError as exc:
            print(f"linux-cmd-mcp: {exc}", file=sys.stderr)
            return 1
        _print_json(payload)
        return 0 if payload.get("running") else 1
    if args.stop:
        try:
            payload = stop_daemon(args.pid_file, timeout=args.stop_timeout)
        except ConfigError as exc:
            print(f"linux-cmd-mcp: {exc}", file=sys.stderr)
            return 1
        _print_json(payload)
        return 0

    env = dict(os.environ)
    if args.log_level:
        env["LCMD_LOG_LEVEL"] = args.log_level

    try:
        settings = Settings.from_env(env)
    except ConfigError as exc:
        print(f"linux-cmd-mcp: configuration error: {exc}", file=sys.stderr)
        return 64

    configure_logging(settings.log_level)

    try:
        host = _normalize_host(args.host or settings.http_host)
        port = args.port if args.port is not None else settings.http_port
        if not 1 <= port <= 65535:
            raise ConfigError(f"端口 {port} 非法", "端口必须在 1..65535 之间。")
    except ConfigError as exc:
        print(f"linux-cmd-mcp: configuration error: {exc}", file=sys.stderr)
        return 64

    # 把 --host/--port 合并进配置快照：--check-config、/healthz 与 serve_http
    # 看到的是同一个实际监听地址，不会出现“显示 127.0.0.1、实际绑 0.0.0.0”。
    settings = settings.with_changes(http_host=host, http_port=port)

    if args.check_config:
        try:
            payload = describe_configuration(settings, args.transport)
        except ConfigError as exc:
            print(f"linux-cmd-mcp: configuration error: {exc}", file=sys.stderr)
            return 64
        _print_json(payload)
        return 0

    if args.daemon:
        try:
            payload = start_daemon(
                settings,
                args.transport,
                host,
                port,
                pid_file=args.pid_file,
                log_file=args.log_file,
                startup_timeout=args.startup_timeout,
                log_level=args.log_level,
            )
        except ConfigError as exc:
            print(f"linux-cmd-mcp: {exc}", file=sys.stderr)
            return 1
        _print_json(payload)
        return 0

    try:
        mcp = build_server(settings)
    except ConfigError as exc:
        print(f"linux-cmd-mcp: configuration error: {exc}", file=sys.stderr)
        return 64

    if settings.policy_mode == "unrestricted":
        logger.warning("policy=unrestricted：任何命令都会放行（等同运行本服务的 Linux 用户权限）")

    try:
        if args.transport == "stdio":
            mcp.run(transport="stdio")
        else:
            serve_http(mcp, settings, args.transport, host=host, port=port)
    except ConfigError as exc:
        print(f"linux-cmd-mcp: configuration error: {exc}", file=sys.stderr)
        return 64
    except KeyboardInterrupt:  # pragma: no cover - 交互式中断
        logger.info("interrupted by user")
        return 130
    except BrokenPipeError:  # 客户端提前关闭管道
        return 0
    finally:
        with contextlib.suppress(Exception):
            logging.getLogger().handlers.clear()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
