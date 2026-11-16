"""把 Pydantic 输入模型转换成“扁平参数”的 MCP tool。

为什么需要它：FastMCP 对 ``async def f(params: SomeModel)`` 会生成
``{"params": {...}}`` 的嵌套 inputSchema，调用方必须多包一层，不符合 MCP
生态的通行写法。这里从模型字段动态构造函数签名（含 Field 约束与描述），
让 schema 保持扁平，同时保持“模型是唯一事实来源”。
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Coroutine
from typing import Annotated, Any

import json
import logging
import types as _pytypes
import typing

from mcp.server.fastmcp import Context
from mcp.server.fastmcp.utilities.func_metadata import FuncMetadata
from pydantic import BaseModel, Field

from ._common import get_state

logger = logging.getLogger("linux_cmd_mcp.sdk_compat")

#: tool 名 -> 入参模型。用于在协议边界做“先校验、再交给 SDK”的结构化报错。
INPUT_MODELS: dict[str, type[BaseModel]] = {}


def build_signature(model: type[BaseModel] | None) -> inspect.Signature:
    """按模型字段构造 ``(*, field=..., ctx: Context)`` 的关键字签名。"""
    parameters: list[inspect.Parameter] = []
    if model is not None:
        for name, field in model.model_fields.items():
            metadata = list(field.metadata or ())
            if field.description:
                metadata.append(Field(description=field.description))
            annotation: Any = Annotated[(field.annotation, *metadata)] if metadata else field.annotation
            if field.is_required() and field.default_factory is None:
                default = inspect.Parameter.empty
            else:
                default = field.get_default(call_default_factory=True)
            parameters.append(
                inspect.Parameter(
                    name,
                    inspect.Parameter.KEYWORD_ONLY,
                    default=default,
                    annotation=annotation,
                )
            )
    parameters.append(
        inspect.Parameter("ctx", inspect.Parameter.KEYWORD_ONLY, annotation=Context)
    )
    return inspect.Signature(parameters)


def make_tool(
    *,
    name: str,
    description: str,
    model: type[BaseModel] | None,
    output: type[BaseModel],
    handler: Callable[..., Coroutine[Any, Any, Any]],
) -> Callable[..., Coroutine[Any, Any, Any]]:
    """生成可直接传给 ``FastMCP.add_tool`` 的包装函数。

    ``handler`` 统一签名为 ``async def handler(state, params, ctx)``。
    """
    if model is not None:
        INPUT_MODELS[name] = model

    signature = build_signature(model).replace(return_annotation=output)
    annotations: dict[str, Any] = {
        parameter: value.annotation
        for parameter, value in signature.parameters.items()
        if value.annotation is not inspect.Parameter.empty
    }
    annotations["return"] = output

    async def tool(**kwargs: Any) -> Any:
        ctx = kwargs.pop("ctx", None)
        params = model.model_validate(kwargs) if model is not None else None
        return await handler(get_state(ctx), params, ctx)

    tool.__signature__ = signature  # type: ignore[attr-defined]
    tool.__annotations__ = annotations
    tool.__name__ = name
    tool.__qualname__ = f"linux_cmd_mcp.tools.{name}"
    tool.__doc__ = description
    return tool


def _annotation_is_string(annotation: object) -> bool:
    """注解是否为纯字符串类型（含 ``str | None`` 这种 Optional 形式）。"""
    if annotation is str:
        return True
    origin = typing.get_origin(annotation)
    if origin is _pytypes.UnionType or origin is typing.Union:
        return any(_annotation_is_string(arg) for arg in typing.get_args(annotation))
    return False


def install_sdk_compat() -> None:
    """修掉 SDK 的一处过度解析：把 JSON 文本型参数误转成 dict/list。

    ``FuncMetadata.pre_parse_json`` 对所有“注解不是 ``str``”的字段都尝试
    ``json.loads``，于是 ``execute_command(stdin='{"a": 1}')`` 会被转成 dict，
    再被 ``str`` 校验拒掉——合法的 JSON 文本无法喂给子进程 stdin。
    这里只对**非字符串字段**保留 SDK 原有的宽松解析（有的宿主会把数组当
    JSON 字符串传），字符串字段一律原样透传。

    SDK 版本被 pyproject 钉死（mcp>=1.30,<1.31），补丁按方法签名生效并幂等。
    """
    if getattr(FuncMetadata, "_lcmd_patched", False):  # pragma: no cover - 幂等
        return

    def pre_parse_json(self: FuncMetadata, data: dict[str, object]) -> dict[str, object]:
        new_data = data.copy()
        for key, value in data.items():
            if not isinstance(value, str):
                continue
            field = self.arg_model.model_fields.get(key)
            if field is not None and _annotation_is_string(field.annotation):
                continue
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, str | int | float):
                continue
            new_data[key] = parsed
        return new_data

    FuncMetadata.pre_parse_json = pre_parse_json  # type: ignore[method-assign]
    FuncMetadata._lcmd_patched = True  # type: ignore[attr-defined]
    logger.debug("SDK pre_parse_json 已收紧：字符串字段不再被 JSON 化")
