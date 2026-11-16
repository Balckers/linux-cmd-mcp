"""路径规范化与工作目录校验的单元测试。"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from linux_cmd_mcp.paths import (
    is_inside,
    match_root,
    normalize_absolute,
    real_path,
    validate_workdir,
)


def test_normalize_expands_home_and_relative(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert normalize_absolute("~/work") == str(tmp_path / "work")
    assert normalize_absolute("a/../b") == os.path.join(os.getcwd(), "b")


@pytest.mark.parametrize("raw", ["", "   ", "bad\x00path"])
def test_normalize_rejects_invalid(raw: str) -> None:
    with pytest.raises(ValueError):
        normalize_absolute(raw)


def test_is_inside_respects_path_components(tmp_path: Path) -> None:
    root = tmp_path / "a"
    root.mkdir()
    sibling = tmp_path / "ab"
    sibling.mkdir()
    assert is_inside(str(root / "child"), str(root))
    assert is_inside(str(root), str(root))
    # 前缀相同但不是父子关系，不能被判为越界通过
    assert not is_inside(str(sibling), str(root))


def test_match_root_returns_first_hit(tmp_path: Path) -> None:
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()
    assert match_root(str(two / "deep"), [str(one), str(two)]) == str(two)
    assert match_root(str(one / "deep"), []) is None


def test_validate_workdir_ok(tmp_path: Path) -> None:
    result = validate_workdir(str(tmp_path), [])
    assert result.status == "ok"
    assert result.usable_as_cwd and result.is_directory and result.readable


def test_validate_workdir_not_found(tmp_path: Path) -> None:
    result = validate_workdir(str(tmp_path / "nope"), [])
    assert result.status == "not_found"
    assert not result.exists and not result.usable_as_cwd
    assert result.checks["exists"] == "failed"


def test_validate_workdir_not_a_directory(tmp_path: Path) -> None:
    file_path = tmp_path / "file.txt"
    file_path.write_text("x", encoding="utf-8")
    result = validate_workdir(str(file_path), [])
    assert result.status == "not_a_directory"
    assert result.exists and not result.is_directory


def test_validate_workdir_outside_allowed_roots(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    result = validate_workdir(str(outside), [str(allowed)])
    assert result.status == "outside_allowed_roots"
    assert result.within_allowed_root is None
    assert result.checks["within_allowed_roots"] == "failed"


def test_validate_workdir_within_allowed_root(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    child = allowed / "child"
    child.mkdir()
    result = validate_workdir(str(child), [str(allowed)])
    assert result.status == "ok"
    assert result.within_allowed_root == str(real_path(str(allowed)))


def test_validate_workdir_require_write(tmp_path: Path, skip_if_root) -> None:
    readonly = tmp_path / "readonly"
    readonly.mkdir()
    readonly.chmod(0o500)
    try:
        result = validate_workdir(str(readonly), [], require_write=True)
        assert result.status == "not_writable"
        assert result.usable_as_cwd is False or result.writable is False
    finally:
        readonly.chmod(0o700)


def test_validate_workdir_permission_denied(tmp_path: Path, skip_if_root) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o000)
    try:
        result = validate_workdir(str(locked), [])
        assert result.status == "permission_denied"
        assert result.readable is False or result.searchable is False
    finally:
        locked.chmod(0o700)


def test_validate_workdir_invalid_path() -> None:
    result = validate_workdir("", [])
    assert result.status == "invalid_path"


def test_validate_workdir_symlink_resolves(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    result = validate_workdir(str(link), [str(target)])
    assert result.status == "ok"
    assert result.within_allowed_root == str(target)
