"""命令发现层测试：PATH 语义、去重、符号链接、稳定排序与缓存。"""

from __future__ import annotations

import stat
from pathlib import Path
from types import SimpleNamespace

from linux_cmd_mcp.discovery import CommandDiscovery, build_scan_dirs, scan_path


def test_build_scan_dirs_statuses(fake_path_env: str, fake_bins: SimpleNamespace) -> None:
    dirs = build_scan_dirs(fake_path_env, base_cwd=str(fake_bins.root))
    statuses = [d.status for d in dirs]
    assert statuses[0] == "scanned"
    assert statuses[1] == "duplicate"  # 重复目录
    assert statuses[2] == "missing"
    assert statuses[3] == "skipped_relative"
    assert statuses[4] == "skipped_virtual_fs"
    assert statuses[5] == "scanned"
    assert all(d.path == "" or d.path.startswith("/") for d in dirs)


def test_empty_path_entry_is_skipped(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    dirs = build_scan_dirs(f"{first}::{second}")
    assert [d.status for d in dirs] == ["scanned", "skipped_empty", "scanned"]


def test_discovery_keeps_all_candidates_in_path_order(fake_path_env: str, fake_bins: SimpleNamespace) -> None:
    dirs, results, commands = scan_path(fake_path_env, base_cwd=str(fake_bins.root))
    candidates = commands["tool-a"]
    assert len(candidates) == 2
    assert [c.path_index for c in candidates] == [0, 5]
    assert candidates[0].path == str(fake_bins.tool_a1)
    assert candidates[1].path == str(fake_bins.tool_a2)


def test_non_executable_and_directories_are_excluded(fake_path_env: str, fake_bins: SimpleNamespace) -> None:
    _, results, commands = scan_path(fake_path_env, base_cwd=str(fake_bins.root))
    assert "tool-b" not in commands
    assert "subdir" not in commands
    bin1_result = next(r for r in results if r.scan_dir.path == str(fake_bins.bin1))
    assert bin1_result.skipped_non_executable == 1
    assert bin1_result.broken_symlinks == 1


def test_symlink_candidate_records_target(fake_path_env: str, fake_bins: SimpleNamespace) -> None:
    _, _, commands = scan_path(fake_path_env, base_cwd=str(fake_bins.root))
    tool_c = commands["tool-c"][0]
    assert tool_c.is_symlink is True
    assert tool_c.symlink_target == str(fake_bins.tool_c)
    assert tool_c.real_path == str(fake_bins.tool_c)


def test_scan_results_are_stable(fake_path_env: str, fake_bins: SimpleNamespace) -> None:
    _, _, first = scan_path(fake_path_env, base_cwd=str(fake_bins.root))
    _, _, second = scan_path(fake_path_env, base_cwd=str(fake_bins.root))
    assert list(first) == list(second)
    assert all(list(v) == list(second[k]) for k, v in first.items())


def test_discovery_cache_and_refresh(fake_bins: SimpleNamespace) -> None:
    path = str(fake_bins.bin2)
    discovery = CommandDiscovery(lambda: path, ttl_seconds=10.0, base_cwd=str(fake_bins.root))
    assert discovery.lookup("tool-later") == ()

    later = fake_bins.bin2 / "tool-later"
    later.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
    later.chmod(later.stat().st_mode | stat.S_IXUSR)

    # TTL 内命中缓存
    assert discovery.lookup("tool-later") == ()
    # refresh 立即可见
    assert discovery.lookup("tool-later", refresh=True)[0].path == str(later)


def test_discovery_follows_path_changes() -> None:
    paths = {"value": "/usr/bin"}
    discovery = CommandDiscovery(lambda: paths["value"], ttl_seconds=0.0)
    assert discovery.lookup("ls", refresh=True)
    paths["value"] = "/bin"
    snapshot = discovery.snapshot()
    assert snapshot.path_env == "/bin"


def test_relative_entry_resolved_note(fake_bins: SimpleNamespace) -> None:
    dirs = build_scan_dirs(fake_bins.rel, base_cwd=str(fake_bins.root))
    assert dirs[0].status == "skipped_relative"
    assert dirs[0].relative_to == str(fake_bins.root)
    assert dirs[0].path == str(fake_bins.root / fake_bins.rel)


def test_default_command_dirs_are_merged_into_scan(make_settings) -> None:
    """标准命令目录必须默认并入扫描，即使 PATH 很短也不漏系统命令。"""
    import os

    from linux_cmd_mcp.discovery import DEFAULT_COMMAND_DIRS
    from linux_cmd_mcp.state import build_state

    settings = make_settings(LCMD_PATH="/usr/bin", LCMD_INCLUDE_DEFAULT_DIRS="1")
    state = build_state(settings)
    entries = {scan_dir.path for scan_dir in state.discovery.snapshot().dirs}
    existing = {os.path.realpath(d) for d in DEFAULT_COMMAND_DIRS if os.path.isdir(d)}
    assert existing, "测试机上一个标准命令目录都没有，环境异常"
    # scanned 或 duplicate 都算“已覆盖”（/bin 与 /usr/bin realpath 相同会被标 duplicate）
    assert existing <= entries

    # 关掉开关后，PATH 之外的标准目录不再出现在扫描表里
    off = build_state(make_settings(LCMD_PATH="/usr/bin", LCMD_INCLUDE_DEFAULT_DIRS="0"))
    off_entries = {scan_dir.path for scan_dir in off.discovery.snapshot().dirs}
    assert off_entries < entries


def test_default_command_dirs_can_be_disabled(make_settings) -> None:
    from linux_cmd_mcp.state import build_state

    settings = make_settings(LCMD_PATH="/usr/bin", LCMD_INCLUDE_DEFAULT_DIRS="0")
    state = build_state(settings)
    paths = {scan_dir.path for scan_dir in state.discovery.snapshot().dirs}
    assert "/snap/bin" not in paths or "/snap/bin" in settings.command_dirs
