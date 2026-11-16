#!/usr/bin/env python3
"""对 linux-cmd-mcp 做一次真实的 stdio 握手与调用自检。

MCP 的 stdio 传输是**逐行 JSON（NDJSON）**分帧，不是 LSP 的 ``Content-Length``
头帧。本脚本按行解析，并显式断言 stdout 里没有任何非 JSON 行、也没有
``Content-Length:`` 头——这正是“日志绝不能写 stdout”的线上事故点。

用法::

    python3 scripts/check_handshake.py
    python3 scripts/check_handshake.py --verbose

退出码 0 表示全部通过；1 表示有断言失败（会打印 FAIL 行与服务器 stderr）。
"""

from __future__ import annotations

import argparse
import json
import os
import select
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

CLIENT_PROTOCOL_VERSION = "2025-06-18"
KNOWN_PROTOCOL_VERSIONS = {"2025-06-18", "2025-03-26", "2024-11-05"}
EXPECTED_TOOLS = {
    "list_commands",
    "describe_command",
    "execute_command",
    "check_command",
    "get_system_info",
    "validate_working_directory",
}


class CheckFailure(Exception):
    """断言失败。"""


def pass_line(message: str) -> None:
    print(f"PASS: {message}")


class StdioClient:
    """最小 MCP stdio 客户端：逐行读写 JSON。"""

    def __init__(self, argv: list[str], env: dict[str, str], cwd: str) -> None:
        self.stderr_path = Path(tempfile.mkstemp(prefix="lcmd-stderr-", suffix=".log")[1])
        self._stderr_handle = self.stderr_path.open("w", encoding="utf-8")
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._stderr_handle,
            text=True,
            bufsize=1,
            env=env,
            cwd=cwd,
        )
        self.lines_read = 0
        self._next_id = 0

    # ---------------------------------------------------------------- 低层
    def send(self, payload: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()

    def read_message(self, timeout: float = 20.0) -> dict[str, Any]:
        assert self.proc.stdout is not None
        ready, _, _ = select.select([self.proc.stdout], [], [], timeout)
        if not ready:
            raise CheckFailure(f"等待服务器响应超时（{timeout}s）")
        line = self.proc.stdout.readline()
        if line == "":
            raise CheckFailure("服务器提前关闭了 stdout")
        if not line.endswith("\n"):
            raise CheckFailure(f"响应不是完整行（缺换行）：{line!r}")
        if line.lower().startswith("content-length:"):
            raise CheckFailure("服务器使用了 Content-Length 分帧；MCP stdio 必须是 NDJSON 逐行帧")
        self.lines_read += 1
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CheckFailure(f"stdout 出现非 JSON 内容：{line!r} ({exc})") from exc
        if message.get("jsonrpc") != "2.0":
            raise CheckFailure(f"响应缺少 jsonrpc=2.0：{message}")
        return message

    # ---------------------------------------------------------------- 高层
    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._next_id += 1
        request_id = self._next_id
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            payload["params"] = params
        self.send(payload)
        while True:
            message = self.read_message()
            if message.get("id") == request_id:
                if "error" in message:
                    raise CheckFailure(f"{method} 返回 JSON-RPC 错误：{message['error']}")
                return message["result"]

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self.send(payload)

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": arguments})

    # ---------------------------------------------------------------- 收尾
    def shutdown(self) -> tuple[int, str]:
        assert self.proc.stdin is not None
        self.proc.stdin.close()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
            raise CheckFailure("关闭 stdin 后服务器未在 10s 内退出")
        self._stderr_handle.close()
        stderr_text = self.stderr_path.read_text(encoding="utf-8", errors="replace")
        self.stderr_path.unlink(missing_ok=True)
        return self.proc.returncode, stderr_text

    def remaining_stdout(self) -> list[str]:
        assert self.proc.stdout is not None
        rest = self.proc.stdout.read()
        return [line for line in rest.splitlines() if line.strip()]


def structured(result: dict[str, Any]) -> dict[str, Any]:
    payload = result.get("structuredContent")
    if not isinstance(payload, dict) or not payload:
        raise CheckFailure(f"响应缺少非空 structuredContent：{str(result)[:200]}")
    return payload


def text_of(result: dict[str, Any]) -> str:
    content = result.get("content") or []
    return "\n".join(item.get("text", "") for item in content if item.get("type") == "text")


def run(verbose: bool = False) -> int:
    project_root = Path(__file__).resolve().parents[1]
    workdir = tempfile.mkdtemp(prefix="lcmd-handshake-")
    env = dict(os.environ)
    env.update(
        {
            "PYTHONUNBUFFERED": "1",
            "LCMD_POLICY_MODE": "standard",
            "LCMD_ALLOWED_WORKDIRS": workdir,
            "LCMD_DISCOVERY_TTL_SECONDS": "0",
            "LCMD_LOG_LEVEL": "INFO",
        }
    )
    src = project_root / "src"
    if src.is_dir():
        env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(src), env.get("PYTHONPATH", "")]))

    client = StdioClient(
        [sys.executable, "-m", "linux_cmd_mcp", "--transport", "stdio"], env, cwd=str(project_root)
    )
    checks = 0
    try:
        # 1) initialize
        result = client.request(
            "initialize",
            {
                "protocolVersion": CLIENT_PROTOCOL_VERSION,
                "capabilities": {"roots": {"listChanged": False}, "sampling": {}},
                "clientInfo": {"name": "lcmd-handshake-check", "version": "0.1.0"},
            },
        )
        version = result.get("protocolVersion")
        if version not in KNOWN_PROTOCOL_VERSIONS:
            raise CheckFailure(f"协商出的 protocolVersion 不在已知集合内：{version}")
        capabilities = result.get("capabilities") or {}
        if "tools" not in capabilities:
            raise CheckFailure(f"initialize 未声明 tools 能力：{capabilities}")
        server_info = result.get("serverInfo") or {}
        if server_info.get("name") != "linux_cmd_mcp":
            raise CheckFailure(f"serverInfo.name 不符：{server_info}")
        pass_line(f"initialize（protocolVersion={version}, serverInfo={server_info.get('name')}）")
        checks += 1

        # 2) notifications/initialized
        client.notify("notifications/initialized")
        pass_line("notifications/initialized")
        checks += 1

        # 3) tools/list：命名、扁平 schema、outputSchema
        tools = client.request("tools/list").get("tools") or []
        names = {tool["name"] for tool in tools}
        if names != EXPECTED_TOOLS:
            raise CheckFailure(f"工具集合不符：{sorted(names)}")
        exec_tool = next(tool for tool in tools if tool["name"] == "execute_command")
        schema = exec_tool.get("inputSchema") or {}
        if schema.get("type") != "object":
            raise CheckFailure(f"inputSchema 不是 object：{schema}")
        if "params" in (schema.get("properties") or {}):
            raise CheckFailure("inputSchema 仍是嵌套 params，调用方需要多包一层")
        required = schema.get("required") or []
        if required != ["command"]:
            raise CheckFailure(f"execute_command 的 required 不符：{required}")
        limits = schema["properties"]["timeout_seconds"]
        # Optional[float] 会被渲染成 anyOf: [{type: number, maximum: ...}, {type: null}]
        resolvers = [limits] + list(limits.get("anyOf") or [])
        if not any(branch.get("maximum") == 3600 for branch in resolvers):
            raise CheckFailure(f"timeout_seconds 缺少 maximum 约束：{limits}")
        for tool in tools:
            if not tool.get("outputSchema"):
                raise CheckFailure(f"{tool['name']} 缺少 outputSchema")
        if not exec_tool.get("description") or len(exec_tool["description"]) < 200:
            raise CheckFailure("execute_command 的 description 过短，缺少给模型的契约说明")
        pass_line(f"tools/list（{len(tools)} 个工具，扁平 schema + outputSchema + 描述契约）")
        checks += 1

        # 4) list_commands：结构化内容
        payload = structured(client.call_tool("list_commands", {"limit": 3}))
        if not payload.get("commands"):
            raise CheckFailure(f"list_commands 未返回候选命令：{payload}")
        if payload["returned"] > 3:
            raise CheckFailure("list_commands 未遵守 limit")
        if not payload.get("scanned_dirs"):
            raise CheckFailure("list_commands 未报告扫描目录明细")
        pass_line(f"tools/call list_commands（total_matched={payload['total_matched']}）")
        checks += 1

        # 5) execute_command dry_run：只返回计划
        plan = structured(
            client.call_tool(
                "execute_command", {"command": "echo", "args": ["hi"], "cwd": workdir, "dry_run": True}
            )
        )
        if not plan.get("dry_run") or not plan.get("plan", {}).get("argv"):
            raise CheckFailure(f"dry_run 未返回执行计划：{plan}")
        if plan["plan"]["argv"][0] != "/usr/bin/echo" and not plan["plan"]["argv"][0].endswith("/echo"):
            raise CheckFailure(f"dry_run 的 argv[0] 不是解析后的绝对路径：{plan['plan']['argv']}")
        pass_line(f"tools/call execute_command (dry_run)（argv={plan['plan']['argv']}）")
        checks += 1

        # 6) execute_command 真实执行
        run_result = structured(client.call_tool("execute_command", {"command": "echo", "args": ["hello"], "cwd": workdir}))
        if run_result.get("exit_code") != 0 or run_result.get("stdout") != "hello\n":
            raise CheckFailure(f"真实执行结果异常：{run_result}")
        pass_line(f"tools/call execute_command（exit_code=0, duration_ms={run_result.get('duration_ms')}）")
        checks += 1

        # 7) 策略拒绝：isError + 结构化错误码
        denied = client.call_tool("execute_command", {"command": "rm", "args": ["-rf", "/tmp/lcmd-should-not-exist"]})
        if not denied.get("isError"):
            raise CheckFailure("rm 未被策略拒绝（isError 缺失）")
        denied_text = text_of(denied)
        if "POLICY_DENIED" not in denied_text:
            raise CheckFailure(f"策略拒绝的文本里没有 POLICY_DENIED：{denied_text[:200]}")
        body = json.loads(denied_text[denied_text.index("{") :])
        if body.get("ok") is not False or body["error"]["code"] != "POLICY_DENIED":
            raise CheckFailure(f"策略拒绝的负载结构不符：{body}")
        pass_line("tools/call rm → isError + JSON 负载（POLICY_DENIED）")
        checks += 1

        # 8) 坏入参（schema 级）也必须 isError
        bad = client.call_tool("list_commands", {"limit": 0})
        if not bad.get("isError"):
            raise CheckFailure("limit=0 未触发 isError")
        pass_line("tools/call list_commands(limit=0) → isError（schema 校验由 SDK 完成）")
        checks += 1

        # 9) 不存在的命令 / 非法 cwd / 危险 env
        for args, expected_code in (
            ({"command": "definitely-not-a-command-xyz", "cwd": workdir}, "COMMAND_NOT_FOUND"),
            ({"command": "echo", "cwd": "/no/such/dir"}, "CWD_NOT_FOUND"),
            ({"command": "echo", "cwd": workdir, "env": {"LD_PRELOAD": "/tmp/e.so"}}, "ENV_KEY_FORBIDDEN"),
            ({"command": "echo", "cwd": workdir, "timeout_seconds": 999}, "LIMIT_EXCEEDED"),
            ({"command": "echo", "cwd": "/tmp"}, "CWD_OUTSIDE_ALLOWED_ROOTS"),
        ):
            response = client.call_tool("execute_command", args)
            if not response.get("isError"):
                raise CheckFailure(f"{args} 未触发 isError")
            body_text = text_of(response)
            if expected_code not in body_text:
                raise CheckFailure(f"{args} 未返回 {expected_code}：{body_text[:160]}")
        pass_line("错误路径（COMMAND_NOT_FOUND / CWD_NOT_FOUND / ENV_KEY_FORBIDDEN / LIMIT_EXCEEDED）")
        checks += 1

        # 10) 单个无参数工具
        sysinfo = structured(client.call_tool("get_system_info", {}))
        if not sysinfo.get("kernel", {}).get("sysname"):
            raise CheckFailure(f"get_system_info 缺少内核信息：{sysinfo}")
        pass_line(f"tools/call get_system_info（{sysinfo['distribution'].get('pretty_name')}）")
        checks += 1

        if verbose:
            print(f"-- 已读取 {client.lines_read} 条 JSON 响应行")

        # 11) 关闭 stdin，检查退出码与 stdout 纯净性
        returncode, stderr_text = client.shutdown()
        leftover = client.remaining_stdout()
        if returncode not in (0, None):
            raise CheckFailure(f"服务器退出码异常：{returncode}\nstderr:\n{stderr_text[-2000:]}")
        if leftover:
            raise CheckFailure(f"stdout 仍有非协议输出：{leftover[:3]}")
        if "Content-Length" in stderr_text:
            raise CheckFailure("stderr 出现 Content-Length，疑似按 LSP 帧处理")
        pass_line(f"stdout 纯净（{client.lines_read} 行全部为 JSON-RPC 2.0，无 Content-Length 头帧）")
        checks += 1
        pass_line(f"服务器正常退出（returncode={returncode}，stderr 仅含日志）")
        checks += 1

        print(f"\n全部 {checks} 项自检通过。")
        return 0
    except CheckFailure as exc:
        print(f"FAIL: {exc}")
        try:
            client.proc.kill()
            client.proc.wait(timeout=5)
        finally:
            stderr_text = client.stderr_path.read_text(encoding="utf-8", errors="replace")
            client.stderr_path.unlink(missing_ok=True)
        print("--- 服务器 stderr ---")
        print(stderr_text[-4000:] or "(空)")
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="linux-cmd-mcp 的 stdio 握手自检")
    parser.add_argument("--verbose", action="store_true", help="打印额外诊断信息")
    args = parser.parse_args(argv)
    return run(verbose=args.verbose)


if __name__ == "__main__":
    sys.exit(main())
