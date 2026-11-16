"""pytest 公共 fixture。"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from linux_cmd_mcp.config import Settings
from linux_cmd_mcp.state import build_state
from linux_cmd_mcp.tools._common import set_current_state


@pytest.fixture
def make_settings():
    """用显式环境变量字典构造 Settings（不受宿主真实环境干扰）。"""

    def _make(**env: str) -> Settings:
        return Settings.from_env({key: str(value) for key, value in env.items()})

    return _make


@pytest.fixture
def state_factory(tmp_path: Path):
    """构造 AppState 并注入进程内单例，使工具可在无请求上下文时调用。"""
    states = []

    def _make(**env: str):
        settings = Settings.from_env({key: str(value) for key, value in env.items()})
        state = build_state(settings)
        set_current_state(state)
        states.append(state)
        return state

    yield _make


def _write_exec(path: Path, body: str = "#!/bin/sh\necho ok\n") -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


@pytest.fixture
def fake_bins(tmp_path: Path) -> SimpleNamespace:
    """构造一棵受控的 PATH 目录树，覆盖重复/不可执行/符号链接/缺失目录。"""
    bin1 = tmp_path / "bin1"
    bin2 = tmp_path / "bin2"
    bin1.mkdir()
    bin2.mkdir()

    tool_a1 = _write_exec(bin1 / "tool-a")
    (bin1 / "tool-b").write_text("not executable\n", encoding="utf-8")  # 无 x 位
    (bin1 / "subdir").mkdir()
    tool_c = _write_exec(bin2 / "tool-c")
    tool_a2 = _write_exec(bin2 / "tool-a")
    (bin1 / "broken").symlink_to(tmp_path / "does-not-exist")
    (bin1 / "tool-c").symlink_to(tool_c)

    missing = tmp_path / "missing-dir"
    rel = "relbin"
    (tmp_path / rel).mkdir()
    _write_exec(tmp_path / rel / "rel-tool")

    return SimpleNamespace(
        root=tmp_path,
        bin1=bin1,
        bin2=bin2,
        tool_a1=tool_a1,
        tool_a2=tool_a2,
        tool_c=tool_c,
        missing=missing,
        rel=rel,
    )


@pytest.fixture
def fake_path_env(fake_bins: SimpleNamespace) -> str:
    """含重复目录、缺失目录、相对目录与 /proc 的 PATH。"""
    return os.pathsep.join(
        [
            str(fake_bins.bin1),
            str(fake_bins.bin1),  # 重复
            str(fake_bins.missing),  # 不存在
            fake_bins.rel,  # 相对
            "/proc",  # 虚拟文件系统
            str(fake_bins.bin2),
        ]
    )


@pytest.fixture
def skip_if_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root 下 os.access 恒为真，权限类断言不适用")


@pytest.fixture(scope="session")
def python_executable() -> str:
    return sys.executable
