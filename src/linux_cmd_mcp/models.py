"""MCP 工具的输出模型（同时作为 outputSchema 与结构化返回）。"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RiskLevel = Literal["read_only", "mutating", "network", "process_control", "privileged", "destructive", "shell_wrapper", "unknown"]

WorkdirStatus = Literal[
    "ok",
    "not_found",
    "not_a_directory",
    "permission_denied",
    "not_writable",
    "outside_allowed_roots",
    "not_accessible",
    "invalid_path",
]

CommandStatus = Literal["ok", "not_found", "not_executable", "ambiguous"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class PolicySummary(_Model):
    """当前生效的策略快照，便于调用方在 dry_run 阶段审计。"""

    mode: str = Field(description="unrestricted / permissive / standard / strict")
    allowlist: list[str] = Field(description="额外放行的命令名")
    denylist_extra: list[str] = Field(description="额外拒绝的命令名")
    denylist_override: bool = Field(description="是否已用 LCMD_DENYLIST 替换内置软名单")
    allowed_workdirs: list[str] = Field(description="允许作为 cwd 的根目录；空表示不做子树限制")
    command_dirs: list[str] = Field(description="额外允许绝对路径执行的目录")
    max_timeout_seconds: float
    default_timeout_seconds: float
    max_output_bytes: int
    max_stdin_bytes: int
    max_args: int
    max_arg_length: int
    max_env_keys: int
    max_concurrency: int
    allow_stdin: bool
    include_default_dirs: bool


class CommandCandidate(_Model):
    """同一条命令在某个 PATH 目录中的具体候选。"""

    name: str = Field(description="命令名（文件名）")
    path: str = Field(description="该候选的绝对路径（符号链接不展开）")
    real_path: str | None = Field(default=None, description="realpath 结果；解析失败时为 null")
    directory: str = Field(description="所在 PATH 目录")
    path_index: int = Field(description="PATH 中的序号，越小优先级越高")
    is_symlink: bool = Field(description="是否为符号链接")
    symlink_target: str | None = Field(default=None, description="符号链接指向的原始字符串")
    executable: bool = Field(description="按 os.access(X_OK) 判定是否可执行")
    allowed: bool = Field(description="是否被策略放行")
    denied: bool = Field(description="是否被策略拒绝")
    risk: RiskLevel = Field(description="风险分类")
    category: str | None = Field(default=None, description="策略命中类别，如 hard_deny / shell_wrapper")
    shadowed: bool = Field(description="是否存在序号更小、同名且可执行的候选把它遮蔽")
    runnable: bool | None = Field(
        default=None,
        description="静态解析（ELF 解释器/shebang/架构）后是否真能 exec；null 表示本次未解析",
    )
    unrunnable_reason: str | None = Field(default=None, description="runnable=false 时的具体原因")


class ScanDirInfo(_Model):
    """PATH 目录的扫描状态，用于审计“为什么这个命令没被看到”。"""

    index: int
    raw: str = Field(description="PATH 中的原始片段")
    path: str = Field(description="规范化后的绝对路径")
    status: Literal["scanned", "missing", "not_a_directory", "duplicate", "skipped_empty", "skipped_virtual_fs", "skipped_relative", "error"]
    note: str | None = None
    entries_scanned: int = 0
    executables_found: int = 0
    skipped_non_executable: int = 0
    broken_symlinks: int = 0


class ListCommandsOutput(_Model):
    total_matched: int = Field(description="匹配的候选行数（同一命令在多个 PATH 目录中各占一行）")
    returned: int
    offset: int
    limit: int
    has_more: bool
    next_offset: int | None = None
    commands: list[CommandCandidate]
    scanned_dirs: list[ScanDirInfo] = Field(description="已扫描的目录及统计")
    skipped_dirs: list[ScanDirInfo] = Field(description="被跳过的目录及原因")
    skipped_dir_count: int = Field(description="被跳过的目录总数（缺失/重复/相对/空/虚拟文件系统）")
    policy: PolicySummary | None = None


class FileStatInfo(_Model):
    path: str
    real_path: str | None
    file_type: Literal["regular_file", "directory", "symlink", "fifo", "socket", "block_device", "character_device", "unknown"]
    size_bytes: int
    mode_octal: str = Field(description="权限位，形如 0755")
    mode_symbolic: str = Field(description="ls -l 风格权限串，如 -rwxr-xr-x")
    uid: int
    gid: int
    owner: str | None = Field(default=None, description="用户名；查不到时为 null")
    group: str | None = Field(default=None, description="组名；查不到时为 null")
    owner_lookup_error: str | None = None
    mtime_iso: str
    inode: int


class DescribeCommandOutput(_Model):
    query: str
    name: str
    status: CommandStatus
    exists: bool
    executable: bool
    selected_path: str | None = Field(description="按 PATH 优先级选中的路径；未找到为 null")
    resolved_real_path: str | None = None
    stat: FileStatInfo | None = None
    symlink_chain: list[str] | None = Field(default=None, description="从命令路径逐级 readlink 的结果")
    candidates: list[CommandCandidate]
    allowed: bool
    denied: bool
    risk: RiskLevel
    category: str | None = None
    notes: list[str] = Field(default_factory=list)
    executability: ExecutabilityInfo | None = Field(
        default=None, description="ELF/shebang 静态解析结果；runnable=false 时给出 execve 的失败原因"
    )
    policy: PolicySummary | None = None


class ExecutabilityInfo(_Model):
    """静态解析出的“能否 exec”结论（不启动进程）。"""

    kind: Literal["elf", "script", "other", "unreadable"]
    runnable: bool
    reason: str | None = None
    interpreter: str | None = Field(default=None, description="ELF 的动态加载器或脚本的 shebang 解释器")
    elf_class: str | None = None
    elf_machine: str | None = None
    notes: list[str] = Field(default_factory=list)


class CheckCommandOutput(_Model):
    query: str
    name: str
    status: CommandStatus
    exists: bool
    executable: bool
    resolved_path: str | None
    real_path: str | None
    candidates: list[CommandCandidate]
    allowed: bool
    denied: bool
    risk: RiskLevel
    category: str | None = None
    message: str
    executability: ExecutabilityInfo | None = Field(
        default=None, description="ELF/shebang 静态解析结果；runnable=false 时给出 execve 的失败原因"
    )
    policy: PolicySummary | None = None


class ExecutionPlan(_Model):
    command: str
    argv: list[str]
    resolved_path: str
    cwd: str
    env: dict[str, str] = Field(description="实际会传给子进程的完整环境变量；值为空字符串时表示显式清空")
    env_keys: list[str]
    timeout_seconds: float
    max_output_bytes: int
    stdin_bytes: int
    risk: RiskLevel
    category: str | None = None
    policy: PolicySummary | None = None
    notes: list[str] = Field(default_factory=list)


class ExecuteCommandOutput(_Model):
    exit_code: int | None = Field(description="进程退出码；被信号终止或超时时为 null")
    signal_name: str | None = Field(description="若被信号终止，返回信号名，如 SIGKILL")
    stdout: str
    stderr: str
    stdout_bytes: int = Field(description="子进程实际产生的 stdout 总字节数（可能大于返回内容）")
    stderr_bytes: int
    stdout_truncated: bool
    stderr_truncated: bool
    duration_ms: int
    timed_out: bool
    truncated: bool = Field(description="stdout 或 stderr 任一被截断")
    command: str
    argv: list[str]
    resolved_path: str
    cwd: str
    started_at: str
    finished_at: str
    dry_run: bool
    decoded_with_replacement: bool = Field(description="输出含非 UTF-8 字节时按替换字符解码")
    plan: ExecutionPlan | None = Field(default=None, description="dry_run 时返回的完整计划")
    policy: PolicySummary | None = None
    notes: list[str] = Field(
        default_factory=list,
        description="调用方需要知道的非致命提示（如 cwd 回退、风险级别、strict 模式限制）",
    )


class KernelInfo(_Model):
    sysname: str | None = None
    release: str | None = None
    version: str | None = None
    machine: str | None = None
    source: str
    error: str | None = None


class DistributionInfo(_Model):
    id: str | None = None
    id_like: list[str] = Field(default_factory=list)
    name: str | None = None
    pretty_name: str | None = None
    version: str | None = None
    version_id: str | None = None
    source: str
    error: str | None = None


class CpuInfo(_Model):
    logical_cores: int | None = None
    affinity_cores: int | None = None
    source: str
    error: str | None = None


class MemoryInfo(_Model):
    total_bytes: int | None = None
    available_bytes: int | None = None
    free_bytes: int | None = None
    swap_total_bytes: int | None = None
    source: str
    error: str | None = None


class UserInfo(_Model):
    name: str | None = None
    uid: int | None = None
    gid: int | None = None
    source: str
    error: str | None = None


class SystemInfoOutput(_Model):
    kernel: KernelInfo
    distribution: DistributionInfo
    architecture: str | None
    hostname: str | None
    hostname_source: str
    cpu: CpuInfo
    memory: MemoryInfo
    python_version: str
    python_implementation: str
    current_user: UserInfo
    degraded: list[str] = Field(description="采集失败的信息源列表；空表示全部成功")
    collected_at: str
    policy: PolicySummary | None = None


class WorkingDirectoryResult(_Model):
    query: str
    path: str = Field(description="规范化（含 ~ 展开）后的绝对路径")
    resolved_path: str | None = Field(description="realpath 结果；不可解析时为 null")
    status: WorkdirStatus
    message: str
    exists: bool
    is_directory: bool
    readable: bool
    writable: bool
    searchable: bool
    usable_as_cwd: bool
    within_allowed_root: str | None = Field(default=None, description="命中的允许根目录；未配置限制时为 null")
    require_write: bool
    checks: dict[str, str] = Field(description="逐项检查结果：ok / failed / not_checked / 具体错误")
    policy: PolicySummary | None = None
