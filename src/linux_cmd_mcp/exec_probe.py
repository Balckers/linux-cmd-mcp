"""不启动进程的可执行性解析：回答“这个文件在当前机器上到底能不能 exec 起来”。

`os.access(X_OK)` 只说明有执行位，不代表能跑：悬空符号链接、缺失解释器的
shebang、缺 `PT_INTERP` 动态加载器、32/64 位或架构不匹配的 ELF 都会在
`execve` 时失败（ENOENT / ENOEXEC / EACCES）。`check_command` 承诺“不启动命令”，
所以用本模块的静态解析给出真实可用性，而不是拿执行位冒充可用。

实现只读文件头，不依赖 `readelf`/`file` 等外部命令：

* ELF：校验 magic、class（32/64）、字节序、`e_machine` 与宿主架构是否一致，
  再从程序头里取 `PT_INTERP`，确认动态加载器存在且可执行。
* 脚本：解析 `#!` 行（含 `/usr/bin/env NAME`），确认解释器存在且可执行；
  首行以 CRLF 结尾（`bad interpreter: ...\\r`）单独标记。
* 其它：既不是 ELF 也没有 shebang → `execve` 会 `ENOEXEC`，标记不可运行。

结果对象在模型里只暴露必要字段（kind/interpreter/runnable/reason），
不泄漏文件内容。
"""

from __future__ import annotations

import os
import platform
import shutil
import stat
from dataclasses import dataclass, field

ELF_MAGIC = b"\x7fELF"
PT_INTERP = 3
EM_NAMES = {
    3: "i386",
    8: "mips",
    20: "ppc",
    21: "ppc64",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
}

_HOST_MACHINE = platform.machine().lower()
_MACHINE_TO_EM = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "armv7l": "arm",
    "armv6l": "arm",
    "i686": "i386",
    "i386": "i386",
}


@dataclass(slots=True)
class ExecProbe:
    """一个候选文件的可执行性结论。"""

    path: str
    kind: str  # elf | script | other | unreadable
    runnable: bool
    reason: str | None = None
    interpreter: str | None = None
    elf_class: str | None = None
    elf_machine: str | None = None
    host_machine: str | None = None
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "runnable": self.runnable,
            "reason": self.reason,
            "interpreter": self.interpreter,
            "elf_class": self.elf_class,
            "elf_machine": self.elf_machine,
            "host_machine": self.host_machine,
            "notes": self.notes,
        }


def _parse_shebang(first_line: bytes) -> tuple[str, str | None] | None:
    """返回 (解释器路径, 第一个参数)；`#!/usr/bin/env python3` 的 arg 是 python3。"""
    if not first_line.startswith(b"#!"):
        return None
    payload = first_line[2:].strip()
    if not payload:
        return ("", None)
    parts = payload.decode("utf-8", "replace").split(None, 1)
    interpreter = parts[0]
    arg = parts[1].strip() if len(parts) > 1 else None
    return (interpreter, arg)


def _resolve_env_shebang(arg: str | None) -> str | None:
    if not arg:
        return None
    # `env -S` 之类少见写法，取第一个非选项词
    words = [word for word in arg.split() if not word.startswith("-")]
    if not words:
        return None
    name = words[0]
    return shutil.which(name)


def _read_elf_interpreter(fh, elf_class: int, endian: str) -> tuple[str | None, str]:
    """读 ELF 程序头，返回 (PT_INTERP 路径, 结论说明)。"""
    import struct

    if elf_class == 2:  # 64 位
        header_fmt = endian + "HHIQQQIHHHHHH"
        fh.seek(16)
        (e_type, e_machine, _version, _entry, e_phoff, _shoff, _flags,
         _ehsize, e_phentsize, e_phnum, _shentsize, _shnum, _shstrndx) = struct.unpack(
            header_fmt, fh.read(struct.calcsize(header_fmt))
        )
        ph_fmt = endian + "IIQQQQQQ"
    elif elf_class == 1:  # 32 位
        header_fmt = endian + "HHIIIIIHHHHHH"
        fh.seek(16)
        (e_type, e_machine, _version, _entry, e_phoff, _shoff, _flags,
         _ehsize, e_phentsize, e_phnum, _shentsize, _shnum, _shstrndx) = struct.unpack(
            header_fmt, fh.read(struct.calcsize(header_fmt))
        )
        ph_fmt = endian + "IIIIIIII"
    else:
        return None, f"未知 ELF class={elf_class}"

    machine = EM_NAMES.get(e_machine, f"EM_{e_machine}")
    expected = _MACHINE_TO_EM.get(_HOST_MACHINE)
    machine_note = ""
    if expected and machine != expected:
        machine_note = f"架构不匹配：程序 {machine}，宿主 {expected}（需要对应 emulator/多架构库）"

    interp: str | None = None
    ph_size = struct.calcsize(ph_fmt)
    for index in range(min(e_phnum, 128)):
        fh.seek(e_phoff + index * e_phentsize)
        raw = fh.read(ph_size)
        if len(raw) < ph_size:
            break
        fields = struct.unpack(ph_fmt, raw)
        p_type = fields[0]
        if p_type != PT_INTERP:
            continue
        if elf_class == 2:
            _t, _flags2, p_offset, _vaddr, _paddr, p_filesz, _memsz, _align = fields
        else:
            p_offset, _vaddr, _paddr, p_filesz, _memsz, _flags2, _align = fields[1:]
        fh.seek(p_offset)
        blob = fh.read(min(p_filesz, 4096))
        interp = blob.split(b"\x00", 1)[0].decode("utf-8", "replace")
        break
    if interp is None and machine_note:
        return None, machine_note
    if interp is None:
        return None, "静态链接（无 PT_INTERP），可直接执行"
    if machine_note:
        return interp, machine_note
    return interp, "存在 PT_INTERP"


def probe_executability(path: str) -> ExecProbe:
    """静态判断 ``path`` 在当前机器能否 ``execve`` 成功。"""
    probe = ExecProbe(path=path, kind="other", runnable=False, host_machine=_HOST_MACHINE)
    try:
        st = os.stat(path)  # 跟随符号链接：悬空链接在这里就是 ENOENT
    except OSError as exc:
        probe.kind = "unreadable"
        probe.reason = f"stat 失败：{exc.strerror}"
        return probe

    if not stat.S_ISREG(st.st_mode):
        probe.kind = "other"
        probe.reason = "不是普通文件（目录/设备/FIFO 等无法作为命令执行）"
        return probe
    if not st.st_mode & stat.S_IXUSR and not os.access(path, os.X_OK):
        probe.reason = "缺少执行权限位（execve 会 EACCES）"
        return probe

    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
            if head == ELF_MAGIC:
                probe.kind = "elf"
                fh.seek(4)
                elf_class = int.from_bytes(fh.read(1), "little")
                data_encoding = fh.read(1)
                probe.elf_class = {1: "ELF32", 2: "ELF64"}.get(elf_class, f"ELF?{elf_class}")
                endian = "<" if data_encoding == b"\x01" else ">"
                interp, note = _read_elf_interpreter(fh, elf_class, endian)
                probe.notes.append(note)
                fh.seek(18)  # e_machine 在 ELF 头的固定偏移
                machine = int.from_bytes(fh.read(2), "little" if endian == "<" else "big")
                probe.elf_machine = EM_NAMES.get(machine, f"EM_{machine}")
                if interp:
                    probe.interpreter = interp
                    if not os.path.isfile(interp):
                        probe.reason = f"缺失动态加载器 {interp}（execve 会 ENOENT）"
                        return probe
                    if not os.access(interp, os.X_OK):
                        probe.reason = f"动态加载器 {interp} 不可执行（execve 会 EACCES）"
                        return probe
                expected = _MACHINE_TO_EM.get(_HOST_MACHINE)
                if expected and probe.elf_machine and probe.elf_machine != expected:
                    probe.reason = f"架构不匹配：程序 {probe.elf_machine}，宿主 {expected}"
                    return probe
                if probe.notes and "架构不匹配" in probe.notes[0]:
                    probe.reason = probe.notes[0]
                    return probe
                probe.runnable = True
                return probe

            if head[:2] == b"#!":
                probe.kind = "script"
                fh.seek(0)
                first_line = fh.readline(512)
                if first_line.endswith(b"\r\n"):
                    probe.notes.append("shebang 行以 CRLF 结束，内核会把它算进解释器名")
                parsed = _parse_shebang(first_line.rstrip(b"\r\n"))
                if not parsed or not parsed[0]:
                    probe.reason = "shebang 为空，无法确定解释器"
                    return probe
                interpreter, arg = parsed
                probe.interpreter = interpreter
                if os.path.basename(interpreter) == "env":
                    resolved = _resolve_env_shebang(arg)
                    if resolved is None:
                        probe.reason = f"/usr/bin/env 找不到解释器 {arg!r}（execve 会 ENOENT）"
                        return probe
                    probe.interpreter = resolved
                    interpreter = resolved
                if not os.path.isabs(interpreter):
                    probe.reason = f"shebang 解释器不是绝对路径：{interpreter}"
                    return probe
                if not os.path.isfile(interpreter):
                    probe.reason = f"shebang 解释器不存在：{interpreter}（execve 会 ENOENT）"
                    return probe
                if not os.access(interpreter, os.X_OK):
                    probe.reason = f"shebang 解释器不可执行：{interpreter}"
                    return probe
                if first_line.endswith(b"\r\n"):
                    probe.reason = "shebang 行含 CR，内核会把 \\r 算进解释器路径（bad interpreter）"
                    return probe
                probe.runnable = True
                return probe

        probe.reason = "既不是 ELF 也没有 shebang（execve 会 ENOEXEC）"
        return probe
    except OSError as exc:
        probe.kind = "unreadable"
        probe.reason = f"读取失败：{exc.strerror}"
        return probe
