"""结构化错误与错误码。

约定：
* 所有业务异常都通过 :class:`ToolFailure` 抛出。
* MCP 层（FastMCP）会把异常转换成 ``CallToolResult(isError=True)``，
  其 text 为 ``Error executing tool <name>: <JSON>``；``<JSON>`` 即
  ``{"ok": false, "error": {...}}``，客户端可从第一个 ``{`` 起解析。
* 协议级错误（未知方法、参数解析失败等）由 SDK 以 JSON-RPC error 返回，
  本模块不处理。
"""

from __future__ import annotations

import enum
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


class ErrorCode(str, enum.Enum):
    """可被客户端程序化分支处理的错误码。"""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    COMMAND_NOT_FOUND = "COMMAND_NOT_FOUND"
    COMMAND_NOT_EXECUTABLE = "COMMAND_NOT_EXECUTABLE"
    COMMAND_PATH_FORBIDDEN = "COMMAND_PATH_FORBIDDEN"
    POLICY_DENIED = "POLICY_DENIED"
    CWD_NOT_FOUND = "CWD_NOT_FOUND"
    CWD_NOT_A_DIRECTORY = "CWD_NOT_A_DIRECTORY"
    CWD_PERMISSION_DENIED = "CWD_PERMISSION_DENIED"
    CWD_OUTSIDE_ALLOWED_ROOTS = "CWD_OUTSIDE_ALLOWED_ROOTS"
    CWD_NOT_ACCESSIBLE = "CWD_NOT_ACCESSIBLE"
    ENV_KEY_FORBIDDEN = "ENV_KEY_FORBIDDEN"
    ENV_VALUE_INVALID = "ENV_VALUE_INVALID"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    SPAWN_FAILED = "SPAWN_FAILED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass(slots=True)
class ToolFailure(Exception):
    """携带结构化负载的业务异常。

    Parameters
    ----------
    code:
        稳定的错误码，客户端可据此分支。
    message:
        面向调用方（通常是模型）的一句话说明。
    hint:
        可执行的下一步建议。
    details:
        附加诊断字段；不得包含密钥、完整环境变量等敏感信息。
    """

    code: ErrorCode
    message: str
    hint: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        error: dict[str, Any] = {"code": self.code.value, "message": self.message}
        if self.hint:
            error["hint"] = self.hint
        if self.details:
            error["details"] = self.details
        return {"ok": False, "error": error}

    def to_json(self) -> str:
        return json.dumps(self.to_payload(), ensure_ascii=False, sort_keys=False)

    def __str__(self) -> str:  # FastMCP 会把这个字符串放进 isError 结果
        return self.to_json()


class ConfigError(Exception):
    """启动期配置错误：直接终止进程，并给出明确修复建议。"""

    def __init__(self, message: str, hint: str | None = None) -> None:
        self.message = message
        self.hint = hint
        text = message if hint is None else f"{message} (hint: {hint})"
        super().__init__(text)


def fail(
    code: ErrorCode,
    message: str,
    hint: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> None:
    """抛出一个业务失败；函数标注为 None 以便在 ``NoReturn`` 位置使用。"""
    raise ToolFailure(code=code, message=message, hint=hint, details=dict(details or {}))


def limit_failure(limit_name: str, value: float, maximum: float, unit: str) -> None:
    """统一的越界拒绝文案，保证各工具口径一致。"""
    fail(
        ErrorCode.LIMIT_EXCEEDED,
        f"{limit_name}={value}{unit} 超过服务端上限 {maximum}{unit}，已拒绝执行。",
        f"把 {limit_name} 降到 <= {maximum}{unit}，或由运维调整 LCMD_MAX_* 配置后重启服务。",
        {"limit": limit_name, "value": value, "maximum": maximum, "unit": unit},
    )
