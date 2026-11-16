#!/usr/bin/env python3
"""用官方 MCP Python SDK 作为客户端，与本服务器跑一轮真实调用。

用法::

    python3 examples/python_client.py                       # 用当前解释器启动服务器
    python3 examples/python_client.py --python /usr/bin/python3 --mode strict

脚本做的事：initialize → tools/list → 依次调用 6 个工具 → 打印结构化结果。
任何一个调用返回 isError 都会把错误负载打印出来，方便排查策略配置。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="linux-cmd-mcp 客户端示例")
    parser.add_argument("--python", default=sys.executable, help="用于启动服务器的 Python 解释器")
    parser.add_argument("--mode", default="standard", choices=("strict", "standard", "permissive"), help="策略模式")
    parser.add_argument("--workdir", default=tempfile.mkdtemp(prefix="lcmd-client-"), help="作为 cwd 的目录")
    return parser.parse_args(argv)


def show(title: str, result) -> None:
    print(f"\n=== {title} ===")
    if result.isError:
        text = "\n".join(item.text for item in result.content if getattr(item, "type", "") == "text")
        print("isError:", text)
        return
    structured = getattr(result, "structuredContent", None)
    print(json.dumps(structured, ensure_ascii=False, indent=2)[:2000] if structured else result.content)


async def main() -> int:
    args = parse_args()
    env = dict(os.environ)
    env.update(
        {
            "LCMD_POLICY_MODE": args.mode,
            "LCMD_ALLOWED_WORKDIRS": args.workdir,
            "LCMD_LOG_LEVEL": "INFO",
        }
    )
    params = StdioServerParameters(
        command=args.python, args=["-m", "linux_cmd_mcp", "--transport", "stdio"], env=env
    )

    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            info = await session.initialize()
            print(f"server: {info.serverInfo.name} {info.serverInfo.version} (protocol {info.protocolVersion})")

            tools = await session.list_tools()
            print("tools:", ", ".join(tool.name for tool in tools.tools))

            show("check_command ls", await session.call_tool("check_command", {"command": "ls"}))
            show(
                "describe_command ls",
                await session.call_tool("describe_command", {"command": "ls", "include_candidates": False}),
            )
            show("list_commands (name=grep)", await session.call_tool("list_commands", {"name_contains": "grep", "limit": 5}))
            show(
                "execute_command dry_run",
                await session.call_tool(
                    "execute_command",
                    {"command": "echo", "args": ["hello"], "cwd": args.workdir, "dry_run": True},
                ),
            )
            show(
                "execute_command real",
                await session.call_tool(
                    "execute_command", {"command": "echo", "args": ["hello"], "cwd": args.workdir}
                ),
            )
            show(
                "execute_command denied (rm)",
                await session.call_tool("execute_command", {"command": "rm", "args": ["-rf", args.workdir]}),
            )
            show("get_system_info", await session.call_tool("get_system_info", {}))
            show(
                "validate_working_directory",
                await session.call_tool("validate_working_directory", {"path": args.workdir, "require_write": True}),
            )
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
