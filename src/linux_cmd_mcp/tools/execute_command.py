"""``execute_command`` 实现：全套校验 -> （可选 dry_run）-> execve 语义执行。

校验顺序固定，且 dry_run 与真实执行走完全相同的路径（只差最后一步）：

1. command 解析（裸名走 PATH，含 '/' 走绝对路径并受命令目录白名单约束）
2. 策略判定（HARD_DENY / 模式 / LCMD_DENYLIST）
3. 可执行性复核（常规文件 + x 位）
4. args 校验（数量、单条长度、总长度、NUL）
5. cwd 校验（存在/目录/权限/允许根目录）
6. env 校验与构造（注入类键一律拒绝）
7. 限额校验（timeout / max_output_bytes / stdin）
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone

from ..errors import ErrorCode, ToolFailure, fail
from ..inputs import ExecuteCommandInput
from ..models import ExecuteCommandOutput, ExecutionPlan
from ..paths import validate_workdir
from ..runner import RunSpec, run_command
from ..state import AppState
from ..exec_probe import probe_executability
from ._common import fail_on_workdir, is_executable_file, policy_summary, require_candidates


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


async def execute_command_impl(
    state: AppState,
    params: ExecuteCommandInput,
    ctx: object | None = None,
) -> ExecuteCommandOutput:
    settings = state.settings
    summary = policy_summary(state)

    resolved = require_candidates(state, params.command)
    selected = resolved.selected
    assert selected is not None  # require_candidates 已保证

    decision = state.policy.evaluate(
        selected.name,
        selected.path,
        allowed_dirs=state.allowed_command_dirs,
    )
    if not decision.allowed:
        fail(
            ErrorCode.POLICY_DENIED,
            decision.deny_reason(selected.name),
            _policy_hint(decision.category),
            {
                "command": selected.name,
                "path": selected.path,
                "risk": decision.risk,
                "category": decision.category,
                "matched_rule": decision.matched_rule,
                "policy_mode": settings.policy_mode,
            },
        )

    if not is_executable_file(selected.path):
        fail(
            ErrorCode.COMMAND_NOT_EXECUTABLE,
            f"文件不可执行：{selected.path}",
            "检查 x 位、noexec 挂载点，或改用 PATH 中另一个候选（describe_command 可查看全部候选）。",
            {"path": selected.path, "candidates": [c.path for c in resolved.candidates]},
        )

    probe = probe_executability(selected.path)
    if not probe.runnable:
        fail(
            ErrorCode.COMMAND_NOT_EXECUTABLE,
            f"文件有执行位但实际无法 exec：{selected.path}（{probe.reason}）",
            "这正是 execve 会失败的原因（悬空链接/缺失解释器/架构不符/无 shebang）。"
            "换 PATH 中另一个候选，或先修好解释器/文件头；check_command 的 executability 可复核。",
            {
                "path": selected.path,
                "kind": probe.kind,
                "interpreter": probe.interpreter,
                "elf_machine": probe.elf_machine,
                "host_machine": probe.host_machine,
                "reason": probe.reason,
            },
        )

    state.policy.check_args(params.args)

    notes: list[str] = []
    # 服务器 cwd 可能在运行期被删除/卸载：os.getcwd() 会抛 ENOENT。
    # 这里显式回退到 "/" 而不是让裸 OSError 冒到协议层（否则客户端只看到
    # “Error executing tool ...” 的非结构化文本）。
    cwd_fallback = False
    try:
        base_cwd = os.getcwd()
    except OSError:
        base_cwd = "/"
        cwd_fallback = True

    cwd_result = validate_workdir(
        params.cwd if params.cwd is not None else base_cwd,
        settings.allowed_workdirs,
        base=base_cwd,
        policy_summary=summary.model_dump(),
    )
    try:
        fail_on_workdir(cwd_result)
    except ToolFailure as exc:
        if cwd_fallback and params.cwd is None:
            # 没有显式 cwd 且服务器 cwd 已消失时，回退目录又不在允许范围内：
            # 返回可诊断的 CWD_NOT_ACCESSIBLE，而不是让人误解的“/ 越界”。
            raise ToolFailure(
                ErrorCode.CWD_NOT_ACCESSIBLE,
                "服务器进程的当前目录已不可访问，回退目录 '/' 也未通过工作目录策略；请显式传 cwd。",
                "显式传 cwd（取值范围见策略的 allowed_workdirs / LCMD_ALLOWED_WORKDIRS），"
                "或重启服务器以恢复一个存在的当前目录。",
                {"fallback_cwd": base_cwd, "workdir_status": cwd_result.status, "checks": dict(cwd_result.checks)},
            ) from exc
        raise
    cwd = cwd_result.resolved_path or cwd_result.path
    if cwd_fallback and params.cwd is None:
        notes.append("服务器进程的当前目录已不可访问，cwd 回退为 '/'；建议显式传 cwd。")

    env = state.policy.build_env(os.environ, params.env)
    timeout = state.policy.resolve_timeout(params.timeout_seconds)
    max_output = state.policy.resolve_output_limit(params.max_output_bytes)
    state.policy.check_stdin(params.stdin)

    argv = [selected.path, *params.args]

    if decision.risk in {"destructive", "privileged", "shell_wrapper"}:
        notes.append(f"该命令风险级别为 {decision.risk}，建议先 dry_run 审核 argv 与 env。")
    if settings.policy_mode == "strict":
        notes.append("当前为 strict 模式：仅内置只读安全集与 LCMD_ALLOWLIST 可执行。")

    plan = ExecutionPlan(
        command=params.command,
        argv=argv,
        resolved_path=selected.path,
        cwd=cwd,
        env=env,
        env_keys=sorted(env),
        timeout_seconds=timeout,
        max_output_bytes=max_output,
        stdin_bytes=len(params.stdin.encode("utf-8", "replace")) if params.stdin is not None else 0,
        risk=decision.risk,  # type: ignore[arg-type]
        category=decision.category,
        policy=summary,
        notes=notes,
    )

    if params.dry_run:
        return ExecuteCommandOutput(
            exit_code=None,
            signal_name=None,
            stdout="",
            stderr="",
            stdout_bytes=0,
            stderr_bytes=0,
            stdout_truncated=False,
            stderr_truncated=False,
            duration_ms=0,
            timed_out=False,
            truncated=False,
            command=params.command,
            argv=argv,
            resolved_path=selected.path,
            cwd=cwd,
            started_at=_now_iso(),
            finished_at=_now_iso(),
            dry_run=True,
            decoded_with_replacement=False,
            plan=plan,
            policy=summary,
            notes=notes,
        )

    spec = RunSpec(
        command=params.command,
        argv=tuple(argv),
        resolved_path=selected.path,
        cwd=cwd,
        env=env,
        timeout_seconds=timeout,
        max_output_bytes=max_output,
        stdin_text=params.stdin,
    )

    try:
        await asyncio.wait_for(state.semaphore.acquire(), timeout=max(5.0, timeout))
    except asyncio.TimeoutError:
        fail(
            ErrorCode.LIMIT_EXCEEDED,
            f"等待并发槽位超时（LCMD_MAX_CONCURRENCY={settings.max_concurrency}）。",
            "减少并发调用，或由运维提高 LCMD_MAX_CONCURRENCY。",
            {"limit": "concurrency", "maximum": settings.max_concurrency},
        )
    try:
        result = await run_command(spec, ctx)
    finally:
        state.semaphore.release()

    return ExecuteCommandOutput(
        exit_code=result.exit_code,
        signal_name=result.signal_name,
        stdout=result.stdout,
        stderr=result.stderr,
        stdout_bytes=result.stdout_bytes,
        stderr_bytes=result.stderr_bytes,
        stdout_truncated=result.stdout_truncated,
        stderr_truncated=result.stderr_truncated,
        duration_ms=result.duration_ms,
        timed_out=result.timed_out,
        truncated=result.stdout_truncated or result.stderr_truncated,
        command=params.command,
        argv=argv,
        resolved_path=selected.path,
        cwd=cwd,
        started_at=result.started_at,
        finished_at=result.finished_at,
        dry_run=False,
        decoded_with_replacement=result.decoded_with_replacement,
        plan=None,
        policy=summary,
        notes=notes,
    )


def _policy_hint(category: str | None) -> str:
    if category == "hard_deny":
        return "硬拒绝命令无法通过配置放行；如确需执行，请在服务器外由人工操作。"
    if category == "path_forbidden":
        return "把可执行文件放进 PATH 目录（或用 LCMD_COMMAND_DIRS 显式放行该目录）。"
    if category == "shell_wrapper":
        return "本服务器不支持 shell 包装器；请直接给出目标命令与 args 数组。"
    if category == "strict_not_allowlisted":
        return "用 LCMD_ALLOWLIST 显式放行，或把 LCMD_POLICY_MODE 调整为 standard。"
    return "用 check_command 确认策略状态，或由运维调整 LCMD_ALLOWLIST / LCMD_DENYLIST。"
