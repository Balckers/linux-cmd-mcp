#!/usr/bin/env python3
"""全系统命令可用性巡检测试（真测，不是只看存在）。

对每个发现的命令做三层判定：

1. **存在/可执行位/策略**：``check_command``（不启动进程）；
2. **能否真的 exec**：``exec_probe.probe_executability`` 静态解析每个候选路径的
   ELF 解释器 / shebang / 架构，抓出悬空链接、缺解释器、CRLF shebang、架构不符；
3. **真的起得来**：对 ``risk=read_only`` 的命令实际执行 ``<cmd> --help``
   （2s 超时、``PAGER=cat``/``TERM=dumb`` 防分页器挂死），确认进程确实被 exec。

判定口径：

* ``ok``：静态可 exec，且（若被真跑）进程真的起来了（任意退出码都算）；
* ``broken``：不存在 / 无执行位 / 静态解析判定 execve 必失败；
* ``hang``：``--help`` 2s 未退出（交互/分页环境问题，不是命令损坏）；
* ``skipped``：非 ``read_only``，为避免副作用不启动（仍做了静态解析）。

用法::

    python3 scripts/check_all_commands.py                  # 全量
    python3 scripts/check_all_commands.py --no-exec        # 只做静态解析，不启动任何命令
    python3 scripts/check_all_commands.py --json reports/command_health.json

退出码：0 = 无 broken；1 = 有 broken（按原因分组列出）。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from linux_cmd_mcp.config import Settings  # noqa: E402
from linux_cmd_mcp.errors import ToolFailure  # noqa: E402
from linux_cmd_mcp.exec_probe import probe_executability  # noqa: E402
from linux_cmd_mcp.inputs import CheckCommandInput, ExecuteCommandInput  # noqa: E402
from linux_cmd_mcp.state import build_state  # noqa: E402
from linux_cmd_mcp.tools._common import set_current_state  # noqa: E402
from linux_cmd_mcp.tools.check_command import check_command_impl  # noqa: E402
from linux_cmd_mcp.tools.execute_command import execute_command_impl  # noqa: E402

PROBE_ENV = {
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TERM": "dumb",
    "PAGER": "cat",
    "MANPAGER": "cat",
    "GIT_PAGER": "cat",
    "SYSTEMD_PAGER": "cat",
    "GIT_TERMINAL_PROMPT": "0",
    "NO_COLOR": "1",
}


def _reason_group(reason: str | None, kind: str) -> str:
    """把自由文本原因归到固定分组，便于统计。"""
    if kind == "unreadable":
        return "unreadable(stat/读取失败)"
    text = reason or ""
    if "缺少执行权限" in text:
        return "no_exec_bit"
    if "解释器不存在" in text or "env 找不到解释器" in text:
        return "missing_interpreter"
    if "动态加载器" in text:
        return "missing_elf_loader"
    if "架构不匹配" in text:
        return "arch_mismatch"
    if "CR" in text or "\r" in text:
        return "crlf_shebang"
    if "ENOEXEC" in text or "没有 shebang" in text:
        return "no_shebang"
    if "不是普通文件" in text:
        return "not_regular_file"
    return "other"


async def inspect_one(state, name: str, do_exec: bool) -> dict[str, object]:
    record: dict[str, object] = {"name": name}
    try:
        check = await check_command_impl(state, CheckCommandInput(command=name))
    except ToolFailure as exc:
        record.update(status="broken", code=exc.code.value, reason=exc.message, stage="check")
        return record

    record.update(
        path=check.resolved_path,
        candidate_count=len(check.candidates),
        exists=check.exists,
        executable=check.executable,
        risk=check.risk,
        allowed=check.allowed,
        check_status=check.status,
        message=check.message,
        executability=(check.executability.model_dump() if check.executability else None),
    )

    # 2) 对每个候选路径做静态 exec 解析（被遮蔽的坏候选也要抓出来）
    broken_candidates = []
    for candidate in check.candidates:
        if not candidate.executable:
            broken_candidates.append(
                {"path": candidate.path, "kind": "unreadable", "reason": "缺少执行权限位（execve 会 EACCES）", "group": "no_exec_bit"}
            )
            continue
        probe = probe_executability(candidate.path)
        if not probe.runnable:
            broken_candidates.append(
                {
                    "path": candidate.path,
                    "kind": probe.kind,
                    "interpreter": probe.interpreter,
                    "reason": probe.reason,
                    "group": _reason_group(probe.reason, probe.kind),
                }
            )
    record["broken_candidates"] = broken_candidates

    if not check.exists:
        record.update(status="broken", code="COMMAND_NOT_FOUND", reason="PATH 中不存在", stage="check")
        return record
    if not check.executable:
        record.update(status="broken", code="COMMAND_NOT_EXECUTABLE", reason="无执行权限", stage="check")
        return record
    if check.executability and not check.executability.runnable:
        record.update(
            status="broken",
            code="COMMAND_NOT_EXECUTABLE",
            reason=check.executability.reason,
            stage="static_exec",
        )
        return record

    # 3) 只读命令真启动一次
    if not do_exec:
        record.update(status="skipped", reason="--no-exec")
        return record
    if check.risk != "read_only":
        record.update(status="skipped", reason=f"risk={check.risk}")
        return record

    try:
        result = await execute_command_impl(
            state,
            ExecuteCommandInput(
                command=check.resolved_path or name,
                args=["--help"],
                cwd="/tmp",
                env=PROBE_ENV,
                timeout_seconds=2,
                max_output_bytes=65536,
            ),
        )
    except ToolFailure as exc:
        record.update(status="broken", code=exc.code.value, reason=exc.message, stage="exec")
        return record

    if result.timed_out:
        record.update(status="hang", code="TIMEOUT", reason="--help 未在 2s 内退出", stage="exec")
        return record
    record.update(
        status="ok",
        exit_code=result.exit_code,
        signal_name=result.signal_name,
        duration_ms=result.duration_ms,
        stderr_head=result.stderr[:120].strip(),
    )
    return record


async def sweep(do_exec: bool, concurrency: int) -> dict[str, object]:
    settings = Settings.from_env(
        {
            "LCMD_POLICY_MODE": "unrestricted",
            "LCMD_MAX_CONCURRENCY": str(concurrency),
            "LCMD_MAX_TIMEOUT_SECONDS": "10",
            "LCMD_ALLOWED_WORKDIRS": "/tmp,/home/user,/opt,/usr,/var,/etc,/root",
            "LCMD_LOG_LEVEL": "ERROR",
        }
    )
    state = build_state(settings)
    set_current_state(state)
    snapshot = state.discovery.snapshot()
    raw = snapshot.commands
    names = sorted(item[0] for item in raw) if not isinstance(raw, dict) else sorted(raw)

    semaphore = asyncio.Semaphore(concurrency)
    started = time.monotonic()

    async def bounded(name: str) -> dict[str, object]:
        async with semaphore:
            return await inspect_one(state, name, do_exec)

    records = await asyncio.gather(*(bounded(name) for name in names))
    elapsed_ms = int((time.monotonic() - started) * 1000)

    counts = Counter(str(record["status"]) for record in records)
    broken = [record for record in records if record["status"] == "broken"]
    hangs = [record for record in records if record["status"] == "hang"]

    broken_paths: dict[str, dict[str, object]] = {}
    groups: Counter[str] = Counter()
    total_candidates = 0
    for record in records:
        candidates = record.get("broken_candidates", [])  # type: ignore[assignment]
        total_candidates += int(record.get("candidate_count", 0) or 0)
        for candidate in candidates:  # type: ignore[union-attr]
            broken_paths[str(candidate["path"])] = candidate
            groups[str(candidate.get("group", "other"))] += 1

    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "host": os.uname().nodename,
        "policy_mode": settings.policy_mode,
        "exec_probe": do_exec,
        "command_names": len(names),
        "candidate_paths": total_candidates,
        "elapsed_ms": elapsed_ms,
        "counts": dict(counts),
        "broken_groups": dict(groups),
        "broken_command_names": sorted({str(r["name"]) for r in broken}),
        "broken_candidates": sorted(broken_paths.values(), key=lambda item: str(item["path"])),
        "hangs": hangs,
        "records": records,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="全系统命令可用性巡检")
    parser.add_argument("--no-exec", action="store_true", help="不启动任何命令，只做静态解析")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--json", default="", help="把完整报告写到该路径")
    args = parser.parse_args(argv)

    report = asyncio.run(sweep(do_exec=not args.no_exec, concurrency=args.concurrency))

    print(
        f"命令名={report['command_names']} 候选路径={report['candidate_paths']} "
        f"耗时={report['elapsed_ms']}ms 模式={report['policy_mode']} 真跑={report['exec_probe']}"
    )
    print("命令级统计:", json.dumps(report["counts"], ensure_ascii=False, sort_keys=True))
    print("坏候选分组:", json.dumps(report["broken_groups"], ensure_ascii=False, sort_keys=True))

    broken_names = report["broken_command_names"]
    if broken_names:
        print(f"\n起不来的命令 {len(broken_names)} 个：{', '.join(broken_names[:30])}")
        for item in report["broken_candidates"][:20]:
            print(f"  - {item['path']} [{item.get('group')}] {item.get('reason')}")
    else:
        print("\n没有起不来的命令：全部通过存在性、执行位与静态 exec 解析。")

    hangs = report["hangs"]
    if hangs:
        print(f"\n--help 2s 未退出 {len(hangs)} 个：{', '.join(str(h['name']) for h in hangs[:20])}")

    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n完整报告已写入：{path}")

    return 1 if broken_names else 0


if __name__ == "__main__":
    try:
        code = main()
    except BrokenPipeError:  # 输出被 head/less 提前关闭时不要甩 traceback
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        code = 0
    sys.exit(code)
