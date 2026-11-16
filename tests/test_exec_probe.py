"""可执行性静态解析测试：ELF / shebang / CRLF / 悬空链接 / 架构不匹配。"""

from __future__ import annotations

import os
import shutil
import stat
import struct
from pathlib import Path

import pytest

from linux_cmd_mcp.exec_probe import probe_executability


def _mk(tmp_path: Path, name: str, body: bytes | str, mode: int = 0o755) -> Path:
    path = tmp_path / name
    if isinstance(body, bytes):
        path.write_bytes(body)
    else:
        path.write_text(body, encoding="utf-8")
    path.chmod(mode)
    return path


def test_valid_script_is_runnable(tmp_path: Path) -> None:
    path = _mk(tmp_path, "good.sh", "#!/bin/sh\necho hi\n")
    probe = probe_executability(str(path))
    assert probe.kind == "script"
    assert probe.runnable is True
    assert probe.interpreter == "/bin/sh"
    assert probe.reason is None


def test_missing_shebang_interpreter_is_not_runnable(tmp_path: Path) -> None:
    path = _mk(tmp_path, "bad.sh", "#!/nonexistent/python9\nprint(1)\n")
    probe = probe_executability(str(path))
    assert probe.kind == "script"
    assert probe.runnable is False
    assert "解释器不存在" in (probe.reason or "")
    assert probe.interpreter == "/nonexistent/python9"


def test_env_shebang_resolves_and_reports_missing(tmp_path: Path) -> None:
    good = _mk(tmp_path, "env-good", "#!/usr/bin/env python3\nprint(1)\n")
    assert probe_executability(str(good)).runnable is True

    bad = _mk(tmp_path, "env-bad", "#!/usr/bin/env python2.7\nprint(1)\n")
    probe = probe_executability(str(bad))
    assert probe.runnable is False
    assert "找不到解释器" in (probe.reason or "")


def test_crlf_shebang_is_not_runnable(tmp_path: Path) -> None:
    path = _mk(tmp_path, "crlf.sh", b"#!/bin/sh\r\necho hi\r\n")
    probe = probe_executability(str(path))
    assert probe.runnable is False
    assert "CR" in (probe.reason or "")


def test_plain_text_without_shebang_is_not_runnable(tmp_path: Path) -> None:
    path = _mk(tmp_path, "plain", "echo hi\n")
    probe = probe_executability(str(path))
    assert probe.kind == "other"
    assert probe.runnable is False
    assert "ENOEXEC" in (probe.reason or "")


def test_no_exec_bit_and_dangling_symlink(tmp_path: Path) -> None:
    no_bit = _mk(tmp_path, "nobit", "#!/bin/sh\necho hi\n", mode=0o644)
    assert probe_executability(str(no_bit)).runnable is False

    link = tmp_path / "dangling"
    os.symlink("/nonexistent/target-for-test", link)
    probe = probe_executability(str(link))
    assert probe.kind == "unreadable"
    assert probe.runnable is False


def test_real_elf_binary_is_runnable() -> None:
    ls = shutil.which("ls")
    if not ls:  # pragma: no cover - 无 ls 的极端环境
        pytest.skip("没有 ls 可测")
    probe = probe_executability(ls)
    assert probe.kind == "elf"
    assert probe.runnable is True
    assert probe.elf_class in {"ELF32", "ELF64"}
    assert probe.interpreter is None or probe.interpreter.startswith("/")


def test_architecture_mismatch_is_detected(tmp_path: Path) -> None:
    """构造一个 e_machine=i386 的空程序头 ELF：宿主若为 x86_64/aarch64 应判不可运行。"""
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # ELF64
    header[5] = 1  # little endian
    header[6] = 1  # version
    # e_type=2 (EXEC), e_machine=3 (i386), e_version=1, e_entry=0
    header[16:18] = struct.pack("<H", 2)
    header[18:20] = struct.pack("<H", 3)
    header[20:24] = struct.pack("<I", 1)
    header[24:32] = struct.pack("<Q", 0)
    header[32:40] = struct.pack("<Q", 0)  # e_phoff
    header[40:48] = struct.pack("<Q", 0)  # e_shoff
    header[48:52] = struct.pack("<I", 0)  # e_flags
    header[52:54] = struct.pack("<H", 64)  # e_ehsize
    header[54:56] = struct.pack("<H", 56)  # e_phentsize
    header[56:58] = struct.pack("<H", 0)   # e_phnum = 0
    path = tmp_path / "fake-i386"
    path.write_bytes(bytes(header))
    path.chmod(0o755)

    probe = probe_executability(str(path))
    assert probe.kind == "elf"
    assert probe.elf_machine == "i386"
    if probe.host_machine in {"x86_64", "aarch64"}:
        assert probe.runnable is False
        assert "架构不匹配" in (probe.reason or "")
    else:  # pragma: no cover
        assert probe.runnable is True


def test_directory_is_not_a_command(tmp_path: Path) -> None:
    probe = probe_executability(str(tmp_path))
    assert probe.runnable is False
    assert probe.kind == "other"
    assert (tmp_path.stat().st_mode & stat.S_IFDIR) != 0
