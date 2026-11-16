"""MCP 工具的输入模型（Pydantic v2，生成完整 JSON Schema）。"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RiskLevel = Literal[
    "read_only",
    "mutating",
    "network",
    "process_control",
    "privileged",
    "destructive",
    "shell_wrapper",
    "unknown",
]


class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class ListCommandsInput(_Input):
    name_contains: str | None = Field(
        default=None,
        max_length=128,
        description="按命令名做大小写不敏感的子串过滤，例如 'git'；省略则不过滤。",
    )
    directory: str | None = Field(
        default=None,
        max_length=4096,
        description="只保留位于该 PATH 目录下的候选；必须是绝对路径，例如 '/usr/bin'。",
    )
    allowed: bool | None = Field(
        default=None,
        description="true 只看策略放行的命令，false 只看被拒绝的命令，省略则全部返回。",
    )
    runnable: bool | None = Field(
        default=None,
        description="true 只看静态解析后真能 exec 的命令，false 只看起不来的；指定后会读文件头（略慢）。",
    )
    risk: list[RiskLevel] | None = Field(
        default=None,
        max_length=8,
        description="按风险分类过滤，例如 ['read_only']；省略则不过滤。",
    )
    limit: int = Field(
        default=100,
        ge=1,
        le=2000,
        description="返回条数上限（命令名数量）。默认 100；要一次列全系统命令可传 2000 配合 offset 分页。",
    )
    offset: int = Field(default=0, ge=0, le=100_000, description="分页偏移，按排序后的命令名计数。")
    sort: Literal["name", "path"] = Field(default="name", description="排序键：命令名或绝对路径。")
    refresh: bool = Field(default=False, description="true 时忽略发现缓存，强制重新扫描 PATH。")


class DescribeCommandInput(_Input):
    command: str = Field(
        min_length=1,
        max_length=4096,
        description="命令名（如 'ls'）或绝对路径（如 '/usr/bin/ls'）。不要传参数，也不要传含空格的命令行。",
    )
    include_candidates: bool = Field(default=True, description="是否返回 PATH 中所有同名候选路径。")


class CheckCommandInput(_Input):
    command: str = Field(
        min_length=1,
        max_length=4096,
        description="要检查的命令名或绝对路径；本工具不会启动该命令。",
    )
    include_candidates: bool = Field(default=True, description="是否返回所有同名候选路径。")


class ExecuteCommandInput(_Input):
    command: str = Field(
        min_length=1,
        max_length=4096,
        description="可执行文件名（如 'git'）或 PATH 目录内的绝对路径（如 '/usr/bin/git'）。禁止传整条命令行。",
    )
    args: list[str] = Field(
        default_factory=list,
        max_length=1024,
        description="参数数组，逐项作为 argv 传递，不做 shell 解析；含 ';' '|' '$()' 的元素会被当作普通字符串。",
    )
    cwd: str | None = Field(
        default=None,
        max_length=4096,
        description="子进程工作目录，绝对路径；省略时使用服务器进程当前目录。相对路径会基于服务器 cwd 解析。",
    )
    env: dict[str, str] | None = Field(
        default=None,
        max_length=256,
        description=(
            "要覆盖/追加的环境变量。unrestricted 档允许任意合法键（含 LD_PRELOAD、PATH）；"
            "standard/strict/permissive 只允许白名单键且拒绝 LD_PRELOAD 等注入类键。"
            "键名必须匹配 ^[A-Za-z_][A-Za-z0-9_]*$。"
        ),
    )
    timeout_seconds: float | None = Field(
        default=None,
        gt=0,
        le=3600,
        description="执行超时（秒）。省略时用服务端默认值；超过 LCMD_MAX_TIMEOUT_SECONDS 会被拒绝。",
    )
    stdin: str | None = Field(
        default=None,
        max_length=4 * 1024 * 1024,
        description="写入子进程 stdin 的文本；省略时不连接 stdin。",
    )
    max_output_bytes: int | None = Field(
        default=None,
        ge=1,
        le=32 * 1024 * 1024,
        description="stdout 与 stderr 各自保留的字节上限；超出部分丢弃但会计入总字节数。",
    )
    dry_run: bool = Field(
        default=False,
        description="true 时只做全套校验并返回执行计划，不启动目标进程；建议写操作先 dry_run。",
    )


class ValidateWorkingDirectoryInput(_Input):
    path: str = Field(
        min_length=1,
        max_length=4096,
        description="待校验目录；相对路径会基于服务器进程 cwd 解析，'~' 会展开。",
    )
    require_write: bool = Field(default=False, description="true 时还要求目录可写（例如要生成产物的场景）。")
