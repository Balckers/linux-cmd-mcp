"""``describe_command`` 实现：返回命令的路径、类型、属主、权限与解析链。

只读元数据操作，不启动任何进程；因此即使命令被策略拒绝，也可以用它排查原因。
"""

from __future__ import annotations

import os

from ..errors import ErrorCode, fail
from ..inputs import DescribeCommandInput
from ..exec_probe import probe_executability
from ..models import DescribeCommandOutput, ExecutabilityInfo
from ..state import AppState
from ._common import (
    enrich_candidates,
    file_stat,
    policy_summary,
    require_candidates,
    symlink_chain,
)


async def describe_command_impl(
    state: AppState, params: DescribeCommandInput, ctx: object | None = None
) -> DescribeCommandOutput:
    resolved = require_candidates(state, params.command)
    candidates = enrich_candidates(state, resolved)
    if not params.include_candidates:
        candidates = candidates[:1]

    selected = candidates[0]
    exists = os.path.lexists(selected.path)
    st = file_stat(selected.path)
    executable = selected.executable

    if not exists:  # 解析后被并发删除
        fail(
            ErrorCode.COMMAND_NOT_FOUND,
            f"命令已不存在：{selected.path}",
            "PATH 或文件系统在解析后发生变化，重新执行 list_commands 后再试。",
            {"command": params.command, "path": selected.path},
        )

    executability = None
    if executable:
        probe = probe_executability(selected.path)
        executability = ExecutabilityInfo(
            kind=probe.kind,
            runnable=probe.runnable,
            reason=probe.reason,
            interpreter=probe.interpreter,
            elf_class=probe.elf_class,
            elf_machine=probe.elf_machine,
            notes=probe.notes,
        )
    status = "ok" if executable and (executability is None or executability.runnable) else "not_executable"
    decision = state.policy.evaluate(selected.name, selected.path, allowed_dirs=state.allowed_command_dirs)

    notes: list[str] = []
    if not executable:
        notes.append("文件存在但当前用户不可执行（缺少 x 位、挂载 noexec 或非普通文件）。")
    elif executability is not None and not executability.runnable:
        notes.append(f"有执行位但 execve 会失败：{executability.reason}")
    if len(candidates) > 1:
        notes.append(
            f"PATH 中共有 {len(candidates)} 个同名候选；序号最小者生效，其余被遮蔽。"
        )
    if selected.is_symlink:
        chain = symlink_chain(selected.path) or []
        if chain:
            notes.append(f"符号链接链：{selected.path} -> " + " -> ".join(chain))
    if decision.reason:
        notes.append(f"策略判定：{decision.reason}")
    if resolved.is_path and not decision.allowed and decision.category == "path_forbidden":
        notes.append("该路径不在允许的命令目录内，execute_command 会直接拒绝。")

    return DescribeCommandOutput(
        query=params.command,
        name=selected.name,
        status=status,  # type: ignore[arg-type]
        exists=True,
        executable=executable,
        selected_path=selected.path,
        resolved_real_path=selected.real_path,
        stat=st,
        symlink_chain=symlink_chain(selected.path),
        candidates=candidates,
        allowed=decision.allowed,
        denied=not decision.allowed,
        risk=decision.risk,  # type: ignore[arg-type]
        category=decision.category,
        notes=notes,
        executability=executability,
        policy=policy_summary(state),
    )
