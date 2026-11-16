"""协议边界的参数守卫与 SDK 兼容补丁（回归测试）。

两件事：
1. 非法参数必须返回结构化 ``INVALID_ARGUMENT``（带字段名），不能被 SDK 的
   英文 pydantic 文本漏出去；
2. SDK 的 ``pre_parse_json`` 不能把 JSON 文本型字符串（stdin）转成 dict。
"""

from __future__ import annotations

import asyncio
import json

from mcp import types as mcp_types
from linux_cmd_mcp.config import Settings
from linux_cmd_mcp.server import build_server
from linux_cmd_mcp.tools._flat import _annotation_is_string, install_sdk_compat
from mcp.server.fastmcp.utilities.func_metadata import ArgModelBase, FuncMetadata


def _guard():
    mcp = build_server(Settings.from_env({"LCMD_POLICY_MODE": "unrestricted", "LCMD_LOG_LEVEL": "ERROR"}))
    handler = mcp._mcp_server.request_handlers[mcp_types.CallToolRequest]
    assert handler is not None
    return handler


def _payload(result) -> dict:
    text = result.root.content[0].text
    return json.loads(text)


def test_guard_rejects_out_of_range() -> None:
    handler = _guard()
    request = mcp_types.CallToolRequest(
        method="tools/call",
        params=mcp_types.CallToolRequestParams(name="list_commands", arguments={"limit": 0}),
    )
    payload = _payload(asyncio.run(handler(request)))
    assert payload["error"]["code"] == "INVALID_ARGUMENT"
    assert payload["error"]["details"]["fields"][0]["field"] == "limit"


def test_guard_rejects_unknown_field() -> None:
    handler = _guard()
    request = mcp_types.CallToolRequest(
        method="tools/call",
        params=mcp_types.CallToolRequestParams(
            name="execute_command", arguments={"command": "true", "timout_seconds": 1}
        ),
    )
    payload = _payload(asyncio.run(handler(request)))
    assert payload["error"]["code"] == "INVALID_ARGUMENT"
    assert "timout_seconds" in payload["error"]["message"]


def test_guard_passes_valid_arguments_through() -> None:
    handler = _guard()
    request = mcp_types.CallToolRequest(
        method="tools/call",
        params=mcp_types.CallToolRequestParams(name="check_command", arguments={"command": "ls"}),
    )
    result = asyncio.run(handler(request))
    assert result.root.isError is False
    assert result.root.structuredContent["status"] == "ok"


def test_pre_parse_keeps_json_strings_for_str_fields() -> None:
    class Args(ArgModelBase):
        stdin: str | None = None
        args: list[str] | None = None

    install_sdk_compat()
    meta = FuncMetadata(arg_model=Args)
    parsed = meta.pre_parse_json({"stdin": '{"a": 1}', "args": '["x", "y"]'})
    assert parsed["stdin"] == '{"a": 1}'          # 字符串字段原样保留
    assert parsed["args"] == ["x", "y"]            # 数组字段仍接受 JSON 字符串（宿主兼容）


def test_annotation_is_string() -> None:
    assert _annotation_is_string(str)
    assert _annotation_is_string(str | None)
    assert not _annotation_is_string(list[str])
