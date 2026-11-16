"""日志配置：stdio 传输下 stdout 只允许协议帧，所有日志必须走 stderr。"""

from __future__ import annotations

import logging
import sys

_FORMAT = "%(asctime)s %(levelname)-8s %(name)s %(message)s"


def configure_logging(level: str = "WARNING") -> None:
    """把根 logger 固定到 stderr，并替换掉任何继承来的 stdout handler。

    这一步是 stdio 服务器的关键：一旦有日志写进 stdout，客户端的 JSON-RPC
    帧解析会直接崩掉（线上最常见的 MCP 事故）。
    """
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter(_FORMAT))

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level.upper())

    logging.captureWarnings(True)


def redact(value: str, keep: int = 4) -> str:
    """日志里对疑似凭据做脱敏：只保留尾部若干字符。"""
    if not value:
        return ""
    if len(value) <= keep:
        return "*" * len(value)
    return "*" * (len(value) - keep) + value[-keep:]
