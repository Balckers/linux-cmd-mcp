"""``validate_working_directory`` 实现。"""

from __future__ import annotations

import os

from ..inputs import ValidateWorkingDirectoryInput
from ..models import WorkingDirectoryResult
from ..paths import validate_workdir
from ..state import AppState
from ._common import policy_summary


async def validate_working_directory_impl(
    state: AppState,
    params: ValidateWorkingDirectoryInput,
    ctx: object | None = None,
) -> WorkingDirectoryResult:
    return validate_workdir(
        params.path,
        state.settings.allowed_workdirs,
        require_write=params.require_write,
        base=os.getcwd(),
        policy_summary=policy_summary(state).model_dump(),
    )
