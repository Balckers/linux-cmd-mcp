"""工具注册：把实现函数包装成 MCP tool（描述、注解、inputSchema）。

工具描述是给模型看的契约：做什么、何时该用/不该用、返回什么形状、
失败会怎样。禁止写营销文案。
"""

from __future__ import annotations


from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..inputs import (
    CheckCommandInput,
    DescribeCommandInput,
    ExecuteCommandInput,
    ListCommandsInput,
    ValidateWorkingDirectoryInput,
)
from ..models import (
    CheckCommandOutput,
    DescribeCommandOutput,
    ExecuteCommandOutput,
    ListCommandsOutput,
    SystemInfoOutput,
    WorkingDirectoryResult,
)
from ..state import AppState
from ._flat import make_tool
from .check_command import check_command_impl
from .describe_command import describe_command_impl
from .execute_command import execute_command_impl
from .get_system_info import get_system_info_impl
from .list_commands import list_commands_impl
from .validate_working_directory import validate_working_directory_impl

LIST_DESCRIPTION = """\
从当前进程的 PATH 动态枚举 Linux 可执行文件，返回每个候选的绝对路径、所在目录、PATH 顺序、是否被策略放行以及风险分类。

何时使用：需要知道系统上有哪些命令可用、某命令来自哪个目录、或排查“命令存在但 execute_command 拒绝执行”。
何时不要用：不要用它列目录内容或读文件（用 execute_command 调 ls/cat）；不要用它做通配符或正则匹配（本工具只做命令名子串过滤）；不要用它判断策略是否放行（那是 check_command 的 allowed/denied）。
返回：分页的候选行（同一命令在多个 PATH 目录中各占一行）+ PATH 扫描统计。skipped_dirs 会显式给出跳过原因：空条目、相对路径、目录缺失、重复目录、/proc 等虚拟文件系统。runnable=true|false 会额外做静态 exec 解析（读 ELF 解释器/shebang），每条候选带 runnable 与 unrunnable_reason，用来一次筛出“装了却起不来的命令”。
失败：仅参数非法时 isError(INVALID_ARGUMENT)；PATH 条目为空时不会报错——仍会扫描 LCMD_INCLUDE_DEFAULT_DIRS 的标准命令目录，把该开关设为 0 才可能得到空结果。
副作用：只读，不执行任何命令。结果有 TTL 缓存（LCMD_DISCOVERY_TTL_SECONDS，默认 5s）；refresh=true 可强制重扫。"""

DESCRIBE_DESCRIPTION = """\
返回单个命令的元数据：绝对路径、文件类型、属主/属组、权限位、所在目录、realpath、符号链接链，以及 PATH 中全部同名候选与策略判定。

何时使用：确认命令真实位置、权限是否可执行、属主是否异常，或在多个同名候选之间判断哪个生效（shadowed=true 表示被更早的 PATH 候选遮蔽）。
何时不要用：不要用它读取文件内容（本工具只返回元数据，不打开文件）；不要用它执行命令。
返回：status=ok/not_executable（有执行位但静态解析判定 execve 必失败时也降级为 not_executable，notes 写明原因）；executability 给出 kind/runnable/reason/interpreter/elf_class/elf_machine；stat 为跟随符号链接后的属性；owner/group 查不到时返回 null 并说明原因，不猜测。
失败：命令不存在时 isError(COMMAND_NOT_FOUND)。存在但不可执行不是错误，会返回 status=not_executable。
副作用：只读，不启动进程。"""

CHECK_DESCRIPTION = """\
检查命令是否存在且可执行，不启动目标命令。返回 status(ok/not_found/not_executable)、resolved_path、全部候选路径与策略判定。

何时使用：调用 execute_command 之前做预检；或需要区分“命令不存在”“存在但不可执行”“存在可执行但被策略拒绝”三种情况。
何时不要用：不要用它运行命令；需要权限位、属主等详细元数据时用 describe_command。
返回：命令缺失时也返回正常结果（status=not_found, exists=false），便于调用方分支；executable 是执行位，executability 才是“真能不能 exec”（悬空链接、缺解释器、CRLF shebang、架构不符都会 runnable=false 并给 reason）；参数非法才 isError。
副作用：只读。"""

EXECUTE_DESCRIPTION = """\
在本地以 execve 语义执行单个命令（参数数组传递，不经 shell）。启动前完成命令解析、策略判定、可执行性复核、cwd/env/限额校验。

何时使用：需要真实运行一条 Linux 命令并拿到 exit_code/stdout/stderr；写操作（cp/mv/mkdir/git）应先 dry_run=true 审阅 argv、cwd、env_keys 与风险级别，再执行。
何时不要用：不要用它拼整条命令行（没有 shell，`ls | grep x` 会作为参数传给 ls）；不要把多条命令塞进 args 期望顺序执行；不要用它做需要交互式 TTY 的程序（vim/top/ssh 登录）；不要用它绕过策略执行被拒绝的命令。
参数要点：command 与 args 分离；cwd 省略时为服务器进程 cwd；env 在 unrestricted 档可设任意合法键（含 LD_PRELOAD/PATH），在 standard/strict/permissive 档只允许白名单键、注入类键返回 ENV_KEY_FORBIDDEN；键名格式非法一律 ENV_KEY_FORBIDDEN。
返回：exit_code（被信号终止或超时时为 null）、signal_name、stdout/stderr 文本、各自总字节数与截断标记、duration_ms、timed_out、started_at/finished_at、argv、resolved_path、cwd。
截断语义：stdout/stderr 各自保留前 max_output_bytes 字节，超出部分丢弃但仍计入 stdout_bytes/stderr_bytes；truncated=true 表示有丢弃。
失败语义：找不到/不可执行（含“有 x 位但缺解释器或加载器”）/策略拒绝/cwd 非法/env 非法/超限都在启动前 isError，details 里给 kind/interpreter/reason 便于定位；启动后非零退出不是错误（exit_code 反映真实结果）；超时返回 timed_out=true 且进程组被 SIGTERM->SIGKILL 回收；客户端取消时同样会终止进程组，不遗留孤儿进程。
限额：timeout_seconds <= LCMD_MAX_TIMEOUT_SECONDS（默认 60），max_output_bytes <= LCMD_MAX_OUTPUT_BYTES（默认 1 MiB），stdin <= LCMD_MAX_STDIN_BYTES；越界直接拒绝，不做静默截断。"""

SYSTEM_INFO_DESCRIPTION = """\
返回非敏感的系统基础信息：内核版本、发行版、架构、主机名、CPU 核心数、内存、Python 版本、当前用户。

何时使用：需要判断发行版/架构以选择命令或路径，或在报告里记录运行环境。
何时不要用：不要用它读取环境变量、进程列表、挂载表等可能含敏感信息的内容；不要用它做性能采样。
返回：kernel/distribution/cpu/memory/current_user 各自带 source 与 error 字段；单一信息源缺失只会让该字段为 null 并出现在 degraded 列表，不会整体失败。
副作用：只读，不启动子进程；不返回密码、令牌或完整环境变量。"""

WORKDIR_DESCRIPTION = """\
校验一个目录能否作为子进程工作目录：是否存在、是否为目录、可读、可执行（cd 需要 x 位）、可写（可选）、是否在允许根目录内。

何时使用：执行写操作前确认输出目录可用；或 execute_command 返回 CWD_* 错误后定位原因。
何时不要用：不要用它创建目录（本工具只校验）；不要用它判断文件是否存在（路径必须是目录）。
返回：status 取值 ok/not_found/not_a_directory/permission_denied/not_writable/outside_allowed_roots/not_accessible/invalid_path，附 checks 逐项结果与命中根目录。
副作用：只读；注意 os.access 以真实 uid 判断，root 下可写判定可能偏宽松。"""


def register_tools(mcp: FastMCP, state: AppState) -> None:
    """把所有工具注册到给定的 FastMCP 实例（扁平入参，outputSchema 由模型生成）。"""
    _ = state  # 状态由 lifespan 注入；此处仅保留签名一致性

    mcp.add_tool(
        make_tool(
            name="list_commands",
            description=LIST_DESCRIPTION,
            model=ListCommandsInput,
            output=ListCommandsOutput,
            handler=list_commands_impl,
        ),
        name="list_commands",
        title="List Linux commands",
        description=LIST_DESCRIPTION,
        annotations=ToolAnnotations(
            title="List Linux commands",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )

    mcp.add_tool(
        make_tool(
            name="describe_command",
            description=DESCRIBE_DESCRIPTION,
            model=DescribeCommandInput,
            output=DescribeCommandOutput,
            handler=describe_command_impl,
        ),
        name="describe_command",
        title="Describe a command",
        description=DESCRIBE_DESCRIPTION,
        annotations=ToolAnnotations(
            title="Describe a command",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )

    mcp.add_tool(
        make_tool(
            name="check_command",
            description=CHECK_DESCRIPTION,
            model=CheckCommandInput,
            output=CheckCommandOutput,
            handler=check_command_impl,
        ),
        name="check_command",
        title="Check command availability",
        description=CHECK_DESCRIPTION,
        annotations=ToolAnnotations(
            title="Check command availability",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )

    mcp.add_tool(
        make_tool(
            name="execute_command",
            description=EXECUTE_DESCRIPTION,
            model=ExecuteCommandInput,
            output=ExecuteCommandOutput,
            handler=execute_command_impl,
        ),
        name="execute_command",
        title="Execute a Linux command",
        description=EXECUTE_DESCRIPTION,
        annotations=ToolAnnotations(
            title="Execute a Linux command",
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=True,
        ),
    )

    mcp.add_tool(
        make_tool(
            name="get_system_info",
            description=SYSTEM_INFO_DESCRIPTION,
            model=None,
            output=SystemInfoOutput,
            handler=get_system_info_impl,
        ),
        name="get_system_info",
        title="Get system information",
        description=SYSTEM_INFO_DESCRIPTION,
        annotations=ToolAnnotations(
            title="Get system information",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )

    mcp.add_tool(
        make_tool(
            name="validate_working_directory",
            description=WORKDIR_DESCRIPTION,
            model=ValidateWorkingDirectoryInput,
            output=WorkingDirectoryResult,
            handler=validate_working_directory_impl,
        ),
        name="validate_working_directory",
        title="Validate working directory",
        description=WORKDIR_DESCRIPTION,
        annotations=ToolAnnotations(
            title="Validate working directory",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
