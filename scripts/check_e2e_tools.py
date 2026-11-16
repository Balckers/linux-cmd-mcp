#!/usr/bin/env python3
"""六个工具的深度端到端验收（走真实 SSE，不是 in-process 直调）。

覆盖三层：

1. **协议层**：initialize、tools/list 的 6 个工具、inputSchema/outputSchema 完整性；
2. **功能层**：每个工具的正常路径真实调用（命令真的被执行、文件真的被创建）；
3. **边界层**：不存在/不可执行/策略拒绝/限额/超时/信号/截断/坏 cwd/坏 env/
   无 shell 语义/并发，逐条验证错误码与字段。

外加：服务器 stderr 日志扫描（不得出现 Traceback / ERROR）。

用法::

    python3 scripts/check_e2e_tools.py            # 起 SSE 服务器 + 全量验收
    python3 scripts/check_e2e_tools.py --verbose  # 打印每个调用的结果摘要

退出码 0 = 全部通过；1 = 有失败项（会打印失败断言、服务器 stderr 尾部）。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.sse import sse_client

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_TOOLS = {
    "check_command",
    "describe_command",
    "execute_command",
    "get_system_info",
    "list_commands",
    "validate_working_directory",
}
WORKDIR_ROOTS = "/tmp,/home/user"


class CheckFailure(Exception):
    pass


class Runner:
    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose
        self.passed = 0
        self.failures: list[str] = []

    def ok(self, message: str) -> None:
        self.passed += 1
        print(f"PASS: {message}")

    def fail(self, message: str) -> None:
        self.failures.append(message)
        print(f"FAIL: {message}")

    def check(self, condition: bool, message: str) -> bool:
        if condition:
            self.ok(message)
        else:
            self.fail(message)
        return condition

    def note(self, message: str) -> None:
        if self.verbose:
            print(f"      {message}")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_ready(port: int, timeout: float = 25.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    url = f"http://127.0.0.1:{port}/healthz"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as response:
                return json.loads(response.read().decode("utf-8") or "{}")
        except Exception:
            time.sleep(0.25)
    raise CheckFailure(f"服务器在 {timeout}s 内未就绪（{url}）")


def start_server(port: int, token: str, log_path: Path) -> subprocess.Popen[str]:
    env = dict(os.environ)
    env.update(
        {
            "PYTHONUNBUFFERED": "1",
            "LCMD_AUTH_TOKEN": token,
            "LCMD_POLICY_MODE": "unrestricted",
            "LCMD_ALLOWED_WORKDIRS": WORKDIR_ROOTS,
            "LCMD_LOG_LEVEL": "INFO",
            "LCMD_DISCOVERY_TTL_SECONDS": "0",
            "LCMD_MAX_TIMEOUT_SECONDS": "60",
        }
    )
    src = PROJECT_ROOT / "src"
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(src), env.get("PYTHONPATH", "")]))
    handle = log_path.open("w", encoding="utf-8")
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "linux_cmd_mcp",
            "--transport",
            "sse",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=handle,
        text=True,
        env=env,
        cwd=str(PROJECT_ROOT),
    )


def structured(result: Any) -> dict[str, Any]:
    data = getattr(result, "structuredContent", None)
    if data is None:
        raise CheckFailure(f"结果没有 structuredContent（isError={result.isError}）：{error_message(result)[:200]}")
    return data


def error_code(result: Any) -> str | None:
    texts = [item.text for item in result.content if getattr(item, "type", "") == "text"]
    joined = "\n".join(texts)
    index = joined.find("{")
    if index < 0:
        return None
    try:
        payload = json.loads(joined[index:])
    except json.JSONDecodeError:
        return None
    return (payload.get("error") or {}).get("code")


def error_message(result: Any) -> str:
    texts = [item.text for item in result.content if getattr(item, "type", "") == "text"]
    return "\n".join(texts)


async def call(session: ClientSession, tool: str, args: dict[str, Any]) -> Any:
    return await session.call_tool(tool, args)


async def expect_error(
    session: ClientSession, runner: Runner, tool: str, args: dict[str, Any], code: str, title: str
) -> None:
    result = await call(session, tool, args)
    actual = error_code(result)
    runner.check(
        bool(result.isError) and actual == code,
        f"{title} -> isError + {code}（实际 {actual}）",
    )
    runner.note(error_message(result)[:200])


async def run_session(session: ClientSession, runner: Runner, dry_dir: Path) -> None:
    # ---------- 协议层 ----------
    info = await session.initialize()
    runner.check(info.serverInfo.name == "linux_cmd_mcp", f"initialize serverInfo.name={info.serverInfo.name}")
    runner.check(bool(info.serverInfo.version), f"serverInfo.version={info.serverInfo.version}")
    runner.check(info.capabilities.tools is not None, "capabilities 声明 tools")

    tools = await session.list_tools()
    names = {tool.name for tool in tools.tools}
    runner.check(names == EXPECTED_TOOLS, f"tools/list 恰好 6 个工具：{sorted(names)}")
    for tool in tools.tools:
        schema = tool.inputSchema or {}
        has_schema = schema.get("type") == "object" and isinstance(schema.get("properties"), dict)
        runner.check(has_schema, f"{tool.name} inputSchema 是带 properties 的 object")
        runner.check(bool(tool.description), f"{tool.name} 有面向模型的 description")
        runner.check(tool.outputSchema is not None, f"{tool.name} 带 outputSchema")

    # ---------- list_commands ----------
    page = structured(await call(session, "list_commands", {"limit": 5}))
    runner.check(len(page["commands"]) == 5, "list_commands limit=5 返回 5 行")
    runner.check(page["has_more"] is True and page["next_offset"] == 5, "list_commands 分页游标正确")
    runner.check(page["total_matched"] > 1000, f"list_commands total_matched={page['total_matched']}")

    filtered = structured(await call(session, "list_commands", {"name_contains": "python", "limit": 50}))
    runner.check(
        all("python" in item["name"] for item in filtered["commands"]),
        "list_commands name_contains=python 过滤正确",
    )

    in_usr_bin = structured(await call(session, "list_commands", {"directory": "/usr/bin", "limit": 50}))
    runner.check(
        all(item["directory"] == "/usr/bin" for item in in_usr_bin["commands"]),
        "list_commands directory=/usr/bin 过滤正确",
    )

    runnable_only = structured(await call(session, "list_commands", {"runnable": True, "limit": 2000}))
    runner.check(
        runnable_only["total_matched"] > 1500 and all(i["runnable"] is True for i in runnable_only["commands"]),
        f"list_commands runnable=true -> {runnable_only['total_matched']} 行且全部可 exec",
    )

    broken_only = structured(await call(session, "list_commands", {"runnable": False, "limit": 2000}))
    runner.check(
        all(i["runnable"] is False and i["unrunnable_reason"] for i in broken_only["commands"]),
        f"list_commands runnable=false -> {broken_only['total_matched']} 行（每行都有原因）",
    )

    head = structured(await call(session, "list_commands", {"limit": 10, "sort": "path"}))
    tail = structured(await call(session, "list_commands", {"limit": 10, "offset": 10, "sort": "path"}))
    head_paths = [i["path"] for i in head["commands"]]
    tail_paths = [i["path"] for i in tail["commands"]]
    runner.check(head_paths == sorted(head_paths), "list_commands sort=path 单调有序")
    runner.check(not (set(head_paths) & set(tail_paths)), "list_commands offset 翻页不重复")

    bad_arg = await call(session, "list_commands", {"limit": 0})
    code = error_code(bad_arg)
    runner.check(bool(bad_arg.isError) and code == "INVALID_ARGUMENT", f"limit=0 -> 结构化 INVALID_ARGUMENT（实际 {code}）")
    payload = json.loads(error_message(bad_arg)[error_message(bad_arg).find("{"):])
    runner.check(
        payload["error"]["details"]["fields"][0]["field"] == "limit",
        "INVALID_ARGUMENT 的 details.fields 指出是 limit",
    )

    typo = await call(session, "execute_command", {"command": "true", "timout_seconds": 1})
    runner.check(bool(typo.isError) and error_code(typo) == "INVALID_ARGUMENT", "未知字段拼错 -> INVALID_ARGUMENT（不静默忽略）")
    await expect_error(session, runner, "list_commands", {"limit": 5000}, "INVALID_ARGUMENT", "limit=5000 越界")

    # ---------- describe_command ----------
    described = structured(await call(session, "describe_command", {"command": "ls"}))
    runner.check(described["status"] == "ok" and described["exists"], "describe_command ls status=ok")
    runner.check(described["selected_path"].startswith("/"), "describe_command 返回绝对路径")
    runner.check(described["stat"]["mode_octal"].startswith("0o"), "describe_command 返回权限位")
    runner.check(described["executability"]["runnable"] is True, "describe_command ls executability.runnable=true")
    runner.check(len(described["candidates"]) >= 1, "describe_command 返回候选列表")

    described_py = structured(await call(session, "describe_command", {"command": "python3"}))
    runner.check(described_py["executability"]["runnable"] is True, "describe_command python3 可执行")

    await expect_error(session, runner, "describe_command", {"command": "no-such-cmd-12345"}, "COMMAND_NOT_FOUND", "describe_command 不存在命令")

    # ---------- check_command ----------
    check_ls = structured(await call(session, "check_command", {"command": "ls", "include_candidates": True}))
    runner.check(check_ls["status"] == "ok" and check_ls["exists"], "check_command ls status=ok")
    runner.check(check_ls["executability"]["runnable"] is True, "check_command ls executability.runnable=true")

    check_x = structured(await call(session, "check_command", {"command": "xkeystone"}))
    runner.check(
        check_x["status"] == "ok" and check_x["executability"]["runnable"] is True,
        "check_command xkeystone 现在可执行（依赖已补齐）",
    )

    check_missing = structured(await call(session, "check_command", {"command": "no-such-cmd-12345"}))
    runner.check(check_missing["status"] == "not_found" and check_missing["exists"] is False, "check_command 不存在 -> not_found 而不是异常")

    # ---------- execute_command：正常执行 ----------
    ls_out = structured(await call(session, "execute_command", {"command": "ls", "args": ["-la", "/tmp"], "cwd": "/tmp"}))
    runner.check(ls_out["exit_code"] == 0 and ls_out["stdout"], "execute_command ls -la /tmp 成功")

    echo_out = structured(await call(session, "execute_command", {"command": "echo", "args": ["你好 world"]}))
    runner.check(echo_out["exit_code"] == 0 and echo_out["stdout"].strip() == "你好 world", "execute_command echo 中文参数回显")

    false_out = structured(await call(session, "execute_command", {"command": "false"}))
    runner.check(false_out["exit_code"] == 1 and false_out["timed_out"] is False, "execute_command false 退出码 1 且不算错误")

    shell_out = structured(
        await call(session, "execute_command", {"command": "sh", "args": ["-c", "printf abc; exit 42"]})
    )
    runner.check(shell_out["exit_code"] == 42 and shell_out["stdout"] == "abc", "execute_command sh -c 传参正确（无隐式 shell 拼接）")

    abs_out = structured(await call(session, "execute_command", {"command": "/usr/bin/ls", "args": ["/tmp"]}))
    runner.check(abs_out["exit_code"] == 0 and abs_out["resolved_path"] == "/usr/bin/ls", "execute_command 绝对路径可执行")

    git_out = structured(await call(session, "execute_command", {"command": "git", "args": ["--version"]}))
    runner.check(git_out["exit_code"] == 0 and "git version" in git_out["stdout"], "execute_command git --version 成功")

    py_out = structured(
        await call(session, "execute_command", {"command": "python3", "args": ["-c", "print(6*7)"]})
    )
    runner.check(py_out["exit_code"] == 0 and py_out["stdout"].strip() == "42", "execute_command python3 -c 成功")

    stdin_out = structured(
        await call(session, "execute_command", {"command": "cat", "args": [], "stdin": "hello-stdin\n"})
    )
    runner.check(stdin_out["exit_code"] == 0 and stdin_out["stdout"] == "hello-stdin\n", "execute_command stdin 传入正常")

    json_stdin = structured(
        await call(session, "execute_command", {"command": "cat", "args": [], "stdin": '{"a": 1}'})
    )
    runner.check(
        json_stdin["exit_code"] == 0 and json_stdin["stdout"] == '{"a": 1}',
        "stdin 里的 JSON 文本原样进入子进程（不会被 SDK 转成 dict）",
    )

    cwd_out = structured(await call(session, "execute_command", {"command": "pwd", "cwd": "/tmp"}))
    runner.check(cwd_out["stdout"].strip() == "/tmp" and cwd_out["cwd"] == "/tmp", "execute_command cwd=/tmp 生效")

    env_out = structured(
        await call(
            session,
            "execute_command",
            {"command": "sh", "args": ["-c", "printf %s \"$LANG\""], "env": {"LANG": "C.UTF-8"}},
        )
    )
    runner.check(env_out["stdout"].strip() == "C.UTF-8", "execute_command 白名单 env 覆盖生效")

    # ---------- execute_command：dry_run 不产生副作用 ----------
    target = dry_dir / "should-not-exist.txt"
    dry = structured(
        await call(
            session,
            "execute_command",
            {"command": "touch", "args": [str(target)], "dry_run": True},
        )
    )
    runner.check(dry["dry_run"] is True and dry["exit_code"] is None, "dry_run 返回计划且 exit_code=null")
    runner.check(dry["plan"]["argv"][0].endswith("touch"), "dry_run plan 的 argv 正确")
    runner.check(not target.exists(), "dry_run 没有真的创建文件")

    real = structured(await call(session, "execute_command", {"command": "touch", "args": [str(target)]}))
    runner.check(real["exit_code"] == 0 and target.exists(), "真实执行 touch 创建了文件")
    target.unlink(missing_ok=True)

    # ---------- execute_command：边界与错误 ----------
    timed = structured(
        await call(session, "execute_command", {"command": "sleep", "args": ["3"], "timeout_seconds": 1})
    )
    runner.check(timed["timed_out"] is True and timed["exit_code"] is None, "timeout_seconds=1 让 sleep 3 超时")
    runner.check(timed["duration_ms"] < 3000, f"超时后进程被回收（duration_ms={timed['duration_ms']}）")

    truncated = structured(
        await call(session, "execute_command", {"command": "seq", "args": ["1", "200000"], "max_output_bytes": 64})
    )
    runner.check(
        truncated["stdout_truncated"] is True and truncated["stdout_bytes"] > 64 and len(truncated["stdout"]) <= 64 + 16,
        "max_output_bytes=64 触发截断且 stdout_bytes 记录真实总量",
    )

    sig = structured(
        await call(session, "execute_command", {"command": "sh", "args": ["-c", "kill -TERM $$"]})
    )
    runner.check(sig["signal_name"] is not None and sig["exit_code"] is None, f"信号终止被识别（signal={sig['signal_name']}）")

    await expect_error(session, runner, "execute_command", {"command": "no-such-cmd-12345"}, "COMMAND_NOT_FOUND", "执行不存在命令")
    await expect_error(
        session, runner, "execute_command", {"command": "sh", "args": ["-c", "true"], "timeout_seconds": 120},
        "LIMIT_EXCEEDED", "timeout_seconds=120 超过 LCMD_MAX_TIMEOUT_SECONDS(60)",
    )
    await expect_error(
        session, runner, "execute_command", {"command": "sh", "args": ["-c", "true"], "timeout_seconds": 9999},
        "INVALID_ARGUMENT", "timeout_seconds=9999 超出 schema 硬上限 3600",
    )
    await expect_error(
        session, runner, "execute_command", {"command": "sh", "args": ["-c", "true"], "max_output_bytes": 0},
        "INVALID_ARGUMENT", "max_output_bytes=0 违反 ge=1",
    )
    await expect_error(
        session, runner, "execute_command", {"command": "sh", "args": ["-c", "true"], "max_output_bytes": 2_000_000},
        "LIMIT_EXCEEDED", "max_output_bytes 超过 LCMD_MAX_OUTPUT_BYTES(1 MiB)",
    )
    await expect_error(
        session, runner, "execute_command", {"command": "true", "args": ["x"] * 300},
        "LIMIT_EXCEEDED", "args 超过 256 个",
    )
    await expect_error(
        session, runner, "execute_command", {"command": "cat", "stdin": "x" * 2_000_000},
        "LIMIT_EXCEEDED", "stdin 超过 1 MiB",
    )
    env_inject = structured(
        await call(session, "execute_command", {"command": "true", "env": {"LD_PRELOAD": "/tmp/evil.so"}})
    )
    runner.check(env_inject["exit_code"] == 0, "unrestricted 档允许设置 LD_PRELOAD（与 POLICY 一致）")
    await expect_error(
        session, runner, "execute_command", {"command": "true", "env": {"BAD-KEY": "x"}},
        "ENV_KEY_FORBIDDEN", "env 键名非法被拒",
    )
    await expect_error(
        session, runner, "execute_command", {"command": "true", "cwd": "/nonexistent-dir-xyz"},
        "CWD_NOT_FOUND", "cwd 不存在",
    )
    await expect_error(
        session, runner, "execute_command", {"command": "true", "cwd": "/etc/passwd"},
        "CWD_NOT_A_DIRECTORY", "cwd 是文件",
    )
    await expect_error(
        session, runner, "execute_command", {"command": "true", "cwd": "/root"},
        "CWD_OUTSIDE_ALLOWED_ROOTS", "cwd 超出允许根",
    )
    await expect_error(
        session, runner, "execute_command", {"command": "ls | wc -l"},
        "COMMAND_NOT_FOUND", "命令里带管道不会被 shell 解释",
    )

    # ---------- validate_working_directory ----------
    ok_dir = structured(await call(session, "validate_working_directory", {"path": "/tmp"}))
    runner.check(
        ok_dir["status"] == "ok" and ok_dir["usable_as_cwd"] is True and ok_dir["is_directory"] is True,
        "validate_working_directory /tmp 通过",
    )
    missing_dir = structured(await call(session, "validate_working_directory", {"path": "/nonexistent-dir-xyz"}))
    runner.check(missing_dir["status"] == "not_found" and missing_dir["exists"] is False, "validate_working_directory 不存在路径")
    file_dir = structured(await call(session, "validate_working_directory", {"path": "/etc/passwd"}))
    runner.check(file_dir["status"] == "not_a_directory" and file_dir["is_directory"] is False, "validate_working_directory 文件不是目录")
    outside = structured(await call(session, "validate_working_directory", {"path": "/root"}))
    runner.check(outside["usable_as_cwd"] is False, f"validate_working_directory /root 不可用作 cwd（status={outside['status']}）")

    # ---------- get_system_info ----------
    sysinfo = structured(await call(session, "get_system_info", {}))
    runner.check(bool(sysinfo["hostname"]), "get_system_info 有 hostname")
    runner.check(bool(sysinfo["kernel"]["release"]), "get_system_info 有内核版本")
    runner.check(bool(sysinfo["distribution"]["name"]), "get_system_info 有发行版")
    runner.check(sysinfo["cpu"]["logical_cores"] > 0, "get_system_info CPU 核心数 > 0")
    runner.check(sysinfo["memory"]["total_bytes"] > 0, "get_system_info 内存总量 > 0")
    runner.check("PATH" not in json.dumps(sysinfo), "get_system_info 不回显完整环境变量")

    # ---------- 真实命令矩阵（证明不是只会 --help）----------
    battery = [
        ("ls", ["/tmp"], "ls /tmp"),
        ("cat", ["/etc/hostname"], "cat /etc/hostname"),
        ("head", ["-n", "1", "/etc/passwd"], "head -n 1 /etc/passwd"),
        ("tail", ["-n", "1", "/etc/passwd"], "tail -n 1 /etc/passwd"),
        ("wc", ["-l", "/etc/passwd"], "wc -l /etc/passwd"),
        ("sort", ["/etc/hostname"], "sort /etc/hostname"),
        ("uniq", ["/etc/hostname"], "uniq /etc/hostname"),
        ("cut", ["-d:", "-f1", "/etc/passwd"], "cut -d: -f1 /etc/passwd"),
        ("sed", ["-n", "1p", "/etc/passwd"], "sed -n 1p /etc/passwd"),
        ("awk", ["-F:", "{print $1}", "/etc/passwd"], "awk -F: '{print $1}' /etc/passwd"),
        ("grep", ["-c", "root", "/etc/passwd"], "grep -c root /etc/passwd"),
        ("find", ["/tmp", "-maxdepth", "0"], "find /tmp -maxdepth 0"),
        ("stat", ["-c", "%s", "/etc/hostname"], "stat -c %s /etc/hostname"),
        ("df", ["-h", "/"], "df -h /"),
        ("du", ["-s", str(dry_dir)], "du -s <临时目录>"),
        ("ps", ["-e"], "ps -e"),
        ("uname", ["-a"], "uname -a"),
        ("id", [], "id"),
        ("whoami", [], "whoami"),
        ("date", ["+%s"], "date +%s"),
        ("printenv", ["HOME"], "printenv HOME"),
        ("tar", ["--version"], "tar --version"),
        ("gzip", ["--version"], "gzip --version"),
        ("curl", ["--version"], "curl --version"),
        ("git", ["--version"], "git --version"),
        ("python3", ["--version"], "python3 --version"),
        ("make", ["--version"], "make --version"),
        ("gcc", ["--version"], "gcc --version"),
        ("jq", ["--version"], "jq --version"),
    ]
    for command, args, title in battery:
        probe = structured(await call(session, "check_command", {"command": command}))
        if probe["status"] == "not_found":
            runner.note(f"{command} 本机未安装（非本项目依赖，跳过）")
            continue
        out = structured(
            await call(session, "execute_command", {"command": command, "args": args, "cwd": "/tmp"})
        )
        ok = out["exit_code"] == 0 and (out["stdout"] or out["stderr"])
        runner.check(bool(ok), f"真实执行 {title}（exit={out['exit_code']}）")

    # ---------- 超时后不遗留孤儿进程 ----------
    await call(session, "execute_command", {"command": "sleep", "args": ["601"], "timeout_seconds": 1})
    gone = False
    seen = ""
    for _ in range(10):
        await asyncio.sleep(0.4)
        leftover = structured(
            await call(session, "execute_command", {"command": "pgrep", "args": ["-a", "-f", "^sleep 601$"]})
        )
        seen = str(leftover["stdout"])
        if leftover["exit_code"] != 0:
            gone = True
            break
    runner.check(gone, f"超时终止后没有遗留 sleep 进程（SIGTERM+SIGKILL 生效；残留={seen!r}）")

    # ---------- 并发 ----------
    burst = await asyncio.gather(
        *(call(session, "execute_command", {"command": "true"}) for _ in range(20)),
        return_exceptions=True,
    )
    runner.check(
        all(not isinstance(item, Exception) and structured(item)["exit_code"] == 0 for item in burst),
        "20 个并发 execute_command 全部成功",
    )

    mixed = await asyncio.gather(
        *(call(session, "check_command", {"command": "ls"}) for _ in range(10)),
        *(call(session, "list_commands", {"limit": 3}) for _ in range(10)),
        return_exceptions=True,
    )
    runner.check(all(not isinstance(item, Exception) for item in mixed), "混合并发 20 次调用无异常")


def scan_log(log_path: Path, runner: Runner) -> None:
    text = log_path.read_text(encoding="utf-8", errors="replace")
    runner.check("Traceback" not in text, "服务器日志无 Traceback")
    runner.check("ERROR" not in text, "服务器日志无 ERROR 级别记录")
    runner.check("unrestricted" in text.lower(), "启动日志包含 unrestricted 警告（可审计）")
    runner.note(text[-800:])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="6 个工具的深度端到端验收")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--rounds", type=int, default=2, help="整轮功能验收重复次数（默认 2）")
    args = parser.parse_args(argv)

    token = "e2e-" + os.urandom(16).hex()
    port = free_port()
    log_path = Path(tempfile.mkstemp(prefix="lcmd-e2e-", suffix=".log")[1])
    server = start_server(port, token, log_path)
    runner = Runner(verbose=args.verbose)
    dry_dir = Path(tempfile.mkdtemp(prefix="lcmd-e2e-"))

    try:
        wait_ready(port)
        asyncio.run(_drive(port, token, runner, dry_dir, max(1, args.rounds)))
    except CheckFailure as exc:
        runner.fail(str(exc))
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
        scan_log(log_path, runner)

    print(f"\n合计：PASS {runner.passed} 项，FAIL {len(runner.failures)} 项")
    if runner.failures:
        for item in runner.failures:
            print(f"  - {item}")
        print("\n--- 服务器 stderr 尾部 ---")
        print(log_path.read_text(encoding="utf-8", errors="replace")[-3000:])
        return 1
    print("深度端到端验收全部通过。")
    return 0


async def _drive(port: int, token: str, runner: Runner, dry_dir: Path, rounds: int) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    for index in range(rounds):
        async with sse_client(f"http://127.0.0.1:{port}/sse", headers=headers) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await run_session(session, runner, dry_dir)
                runner.note(f"第 {index + 1}/{rounds} 轮会话完成")

    # 第二个独立会话：验证会话之间互不串状态
    async with sse_client(f"http://127.0.0.1:{port}/sse", headers=headers) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            repeat = structured(await call(session, "execute_command", {"command": "echo", "args": ["session-2"]}))
            runner.check(repeat["stdout"].strip() == "session-2", "第二个独立 SSE 会话可用")
            again = structured(await call(session, "list_commands", {"limit": 3}))
            runner.check(len(again["commands"]) == 3, "第二个会话 list_commands 正常")


if __name__ == "__main__":
    sys.exit(main())
