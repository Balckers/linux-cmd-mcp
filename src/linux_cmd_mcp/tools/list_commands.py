"""``list_commands`` 实现：从 PATH 动态枚举可执行文件。"""

from __future__ import annotations

from ..errors import ErrorCode, fail
from ..inputs import ListCommandsInput
from ..models import ListCommandsOutput
from ..paths import normalize_absolute, real_path
from ..state import AppState
from ._common import ResolvedQuery, enrich_candidates, policy_summary, scan_dir_info


async def list_commands_impl(
    state: AppState, params: ListCommandsInput, ctx: object | None = None
) -> ListCommandsOutput:
    snapshot = state.discovery.snapshot(refresh=params.refresh)

    directory_filter: str | None = None
    if params.directory is not None:
        try:
            directory_filter = real_path(normalize_absolute(params.directory))
        except ValueError as exc:
            fail(
                ErrorCode.INVALID_ARGUMENT,
                f"directory 参数非法：{exc}",
                "传入 PATH 中的绝对目录，例如 '/usr/bin'。",
                {"directory": params.directory},
            )

    probe_exec = params.runnable is not None
    rows = []
    for name, candidates in snapshot.commands:
        if params.name_contains and params.name_contains.lower() not in name.lower():
            continue
        resolved = ResolvedQuery(query=name, name=name, is_path=False, candidates=candidates)
        for model in enrich_candidates(state, resolved, probe_exec=probe_exec):
            if directory_filter is not None and real_path(model.directory) != directory_filter:
                continue
            if params.allowed is not None and model.allowed != params.allowed:
                continue
            if params.risk and model.risk not in params.risk:
                continue
            if params.runnable is not None and model.runnable != params.runnable:
                continue
            rows.append(model)

    if params.sort == "path":
        rows.sort(key=lambda item: (item.path, item.name))
    else:
        rows.sort(key=lambda item: (item.name, item.path_index, item.path))

    total = len(rows)
    offset = params.offset
    limit = params.limit
    window = rows[offset : offset + limit]
    has_more = offset + len(window) < total

    results_by_index = {result.scan_dir.index: result for result in snapshot.results}
    scanned = [
        scan_dir_info(scan_dir, results_by_index.get(scan_dir.index))
        for scan_dir in snapshot.dirs
        if scan_dir.status == "scanned"
    ]
    skipped = [scan_dir_info(scan_dir) for scan_dir in snapshot.dirs if scan_dir.status != "scanned"]

    return ListCommandsOutput(
        total_matched=total,
        returned=len(window),
        offset=offset,
        limit=limit,
        has_more=has_more,
        next_offset=offset + len(window) if has_more else None,
        commands=window,
        scanned_dirs=scanned,
        skipped_dirs=skipped,
        skipped_dir_count=len(skipped),
        policy=policy_summary(state),
    )
