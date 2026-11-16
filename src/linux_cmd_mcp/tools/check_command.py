"""``check_command`` 实现：只判断是否存在且可执行，不启动目标命令。

与 ``describe_command`` 的差别：命令缺失时本工具返回正常结果（status=not_found），
便于调用方分支；``describe_command`` 则返回 isError。
"""

from __future__ import annotations

import os

from ..exec_probe import probe_executability
from ..inputs import CheckCommandInput
from ..models import CheckCommandOutput, ExecutabilityInfo
from ..state import AppState
from ._common import enrich_candidates, policy_summary, resolve_candidates


async def check_command_impl(
    state: AppState, params: CheckCommandInput, ctx: object | None = None
) -> CheckCommandOutput:
    resolved = resolve_candidates(state, params.command)
    candidates = enrich_candidates(state, resolved)
    if not params.include_candidates and candidates:
        candidates = candidates[:1]

    selected = candidates[0] if candidates else None
    exists = bool(selected and os.path.lexists(selected.path))
    executable = bool(selected and selected.executable)
    executability: ExecutabilityInfo | None = None

    if selected is None:
        status = "not_found"
        message = f"在 PATH 中找不到可执行文件：{resolved.name}"
        allowed = denied = False
        risk = "unknown"
        category = None
        resolved_path = real = None
    else:
        decision = state.policy.evaluate(selected.name, selected.path, allowed_dirs=state.allowed_command_dirs)
        allowed = decision.allowed
        denied = not decision.allowed
        risk = decision.risk
        category = decision.category
        resolved_path = selected.path
        real = selected.real_path
        if not exists:
            status = "not_found"
            message = f"路径不存在：{selected.path}"
        elif not executable:
            status = "not_executable"
            message = f"命令存在但不可执行：{selected.path}"
        else:
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
            if probe.runnable:
                status = "ok"
                message = f"命令可用：{selected.path}"
            else:
                status = "not_executable"
                message = f"有执行位但实际无法 exec：{selected.path}（{probe.reason}）"
        if denied and decision.reason:
            message += f"（策略：{decision.reason}）"

    return CheckCommandOutput(
        query=params.command,
        name=resolved.name,
        status=status,  # type: ignore[arg-type]
        exists=exists,
        executable=executable,
        resolved_path=resolved_path,
        real_path=real,
        candidates=candidates,
        allowed=allowed,
        denied=denied,
        risk=risk,  # type: ignore[arg-type]
        category=category,
        message=message,
        executability=executability,
        policy=policy_summary(state),
    )
