"""``get_system_info`` 实现。"""

from __future__ import annotations

from ..models import SystemInfoOutput
from ..state import AppState
from ..sysinfo import collect_system_info
from ._common import policy_summary


async def get_system_info_impl(
    state: AppState, params: object | None = None, ctx: object | None = None
) -> SystemInfoOutput:
    return collect_system_info(policy_summary(state).model_dump())
