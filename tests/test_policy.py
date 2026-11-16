"""策略层测试：模式优先级、硬拒绝、环境白名单、参数与限额。"""

from __future__ import annotations

import os

import pytest

from linux_cmd_mcp.config import Settings
from linux_cmd_mcp.errors import ErrorCode, ToolFailure
from linux_cmd_mcp.policy import PolicyEngine


def engine(**env: str) -> PolicyEngine:
    """默认档位（unrestricted）的引擎；护栏测试用 guard() 显式切到 standard。"""
    return PolicyEngine(Settings.from_env({k: str(v) for k, v in env.items()}), command_dirs=("/usr/bin", "/bin"))


def guard(**env: str) -> PolicyEngine:
    """显式 standard 档位：断言护栏行为时必须用它，不依赖默认值。"""
    env.setdefault("LCMD_POLICY_MODE", "standard")
    return engine(**env)


@pytest.mark.parametrize("mode", ["strict", "standard", "permissive"])
def test_hard_deny_in_every_mode(mode: str) -> None:
    policy = engine(LCMD_POLICY_MODE=mode)
    for name in ("sudo", "mkfs", "dd", "systemctl", "mount"):
        decision = policy.evaluate(name, f"/usr/bin/{name}")
        assert decision.allowed is False
        assert decision.category == "hard_deny"


def test_standard_mode_allows_read_only_and_denies_soft() -> None:
    policy = guard()
    assert policy.evaluate("ls", "/usr/bin/ls").allowed is True
    assert policy.evaluate("grep", "/usr/bin/grep").allowed is True
    decision = policy.evaluate("rm", "/usr/bin/rm")
    assert decision.allowed is False
    assert decision.category == "file_delete"
    assert decision.matched_rule == "soft_deny:rm"


def test_standard_denies_shell_wrappers() -> None:
    policy = guard()
    for name in ("bash", "sh", "env", "xargs"):
        decision = policy.evaluate(name, f"/usr/bin/{name}")
        assert decision.allowed is False
        assert decision.risk == "shell_wrapper"


def test_strict_mode_limits_to_safe_set_and_allowlist() -> None:
    policy = engine(LCMD_POLICY_MODE="strict", LCMD_ALLOWLIST="make")
    assert policy.evaluate("ls", "/usr/bin/ls").allowed is True
    assert policy.evaluate("make", "/usr/bin/make").allowed is True
    assert policy.evaluate("vim", "/usr/bin/vim").allowed is False
    assert policy.evaluate("vim", "/usr/bin/vim").category == "strict_not_allowlisted"


def test_permissive_allows_soft_deny_but_still_blocks_hard() -> None:
    policy = engine(LCMD_POLICY_MODE="permissive")
    assert policy.evaluate("rm", "/usr/bin/rm").allowed is True
    assert policy.evaluate("sudo", "/usr/bin/sudo").allowed is False


def test_operator_denylist_applies_in_permissive() -> None:
    policy = engine(LCMD_POLICY_MODE="permissive", LCMD_DENYLIST="curl")
    decision = policy.evaluate("curl", "/usr/bin/curl")
    assert decision.allowed is False
    assert decision.category == "operator_deny"


def test_denylist_override_replaces_soft_list() -> None:
    policy = guard(LCMD_DENYLIST_OVERRIDE="1", LCMD_DENYLIST="chmod")
    assert policy.evaluate("rm", "/usr/bin/rm").allowed is True  # 内置软名单被替换
    assert policy.evaluate("chmod", "/usr/bin/chmod").allowed is False
    assert policy.evaluate("sudo", "/usr/bin/sudo").allowed is False  # 硬拒绝仍在


def test_allowlist_conflict_with_denylist_is_config_error(make_settings) -> None:
    from linux_cmd_mcp.errors import ConfigError

    with pytest.raises(ConfigError):
        make_settings(LCMD_ALLOWLIST="git", LCMD_DENYLIST="git")


def test_path_outside_command_dirs_is_denied() -> None:
    policy = guard()
    decision = policy.evaluate("ls", "/tmp/evil/ls", allowed_dirs=("/usr/bin", "/bin"))
    assert decision.allowed is False
    assert decision.category == "path_forbidden"


def test_risk_classification() -> None:
    policy = engine()
    assert policy.risk_of("ls") == ("read_only", "read_only")
    assert policy.risk_of("curl") == ("network", "http")
    assert policy.risk_of("rm") == ("destructive", "file_delete")
    assert policy.risk_of("totally-unknown-cmd") == ("unknown", None)


def test_build_env_filters_base_environment() -> None:
    policy = engine()
    base = {
        "HOME": "/home/agent",
        "LANG": "C.UTF-8",
        "PATH": "/usr/bin",
        "AWS_SECRET_ACCESS_KEY": "super-secret",
        "SSH_AUTH_SOCK": "/tmp/agent.sock",
    }
    env = policy.build_env(base, None)
    assert env["HOME"] == "/home/agent"
    assert env["LANG"] == "C.UTF-8"
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "SSH_AUTH_SOCK" not in env
    assert env["PATH"] == Settings.from_env({}).effective_path_env()


def test_build_env_rejects_injection_keys() -> None:
    policy = guard()
    for key in ("LD_PRELOAD", "PYTHONPATH", "BASH_ENV"):
        with pytest.raises(ToolFailure) as exc:
            policy.build_env(os.environ, {key: "/tmp/x"})
        assert exc.value.code is ErrorCode.ENV_KEY_FORBIDDEN


def test_build_env_rejects_path_override() -> None:
    policy = guard()
    with pytest.raises(ToolFailure) as exc:
        policy.build_env(os.environ, {"PATH": "/tmp/evil"})
    assert exc.value.code is ErrorCode.ENV_KEY_FORBIDDEN


def test_build_env_rejects_unknown_key_and_allows_extra() -> None:
    policy = guard()
    with pytest.raises(ToolFailure) as exc:
        policy.build_env(os.environ, {"MY_FLAG": "1"})
    assert exc.value.code is ErrorCode.ENV_KEY_FORBIDDEN

    permissive_env = engine(LCMD_ENV_ALLOWLIST_EXTRA="MY_FLAG")
    env = permissive_env.build_env(os.environ, {"MY_FLAG": "1"})
    assert env["MY_FLAG"] == "1"


def test_build_env_limits_key_count() -> None:
    policy = engine(LCMD_MAX_ENV_KEYS="0")
    with pytest.raises(ToolFailure) as exc:
        policy.build_env(os.environ, {"LANG": "C"})
    assert exc.value.code is ErrorCode.LIMIT_EXCEEDED


def test_check_args_limits() -> None:
    policy = engine(LCMD_MAX_ARGS="2", LCMD_MAX_ARG_LENGTH="5")
    policy.check_args(["a", "b"])
    with pytest.raises(ToolFailure) as exc:
        policy.check_args(["a", "b", "c"])
    assert exc.value.code is ErrorCode.LIMIT_EXCEEDED

    with pytest.raises(ToolFailure) as exc:
        policy.check_args(["toolong"])
    assert exc.value.code is ErrorCode.LIMIT_EXCEEDED

    with pytest.raises(ToolFailure) as exc:
        policy.check_args(["bad\x00arg"])
    assert exc.value.code is ErrorCode.INVALID_ARGUMENT


def test_timeout_and_output_limits() -> None:
    policy = engine(LCMD_MAX_TIMEOUT_SECONDS="30", LCMD_DEFAULT_TIMEOUT_SECONDS="10", LCMD_MAX_OUTPUT_BYTES="4096")
    assert policy.resolve_timeout(None) == 10.0
    assert policy.resolve_timeout(5) == 5.0
    with pytest.raises(ToolFailure) as exc:
        policy.resolve_timeout(31)
    assert exc.value.code is ErrorCode.LIMIT_EXCEEDED

    assert policy.resolve_output_limit(None) == 4096
    with pytest.raises(ToolFailure) as exc:
        policy.resolve_output_limit(8192)
    assert exc.value.code is ErrorCode.LIMIT_EXCEEDED


def test_stdin_policy() -> None:
    policy = engine(LCMD_ALLOW_STDIN="0")
    with pytest.raises(ToolFailure) as exc:
        policy.check_stdin("hello")
    assert exc.value.code is ErrorCode.POLICY_DENIED

    enabled = engine(LCMD_MAX_STDIN_BYTES="4")
    with pytest.raises(ToolFailure) as exc:
        enabled.check_stdin("12345")
    assert exc.value.code is ErrorCode.LIMIT_EXCEEDED


# --------------------------------------------------------------------------- unrestricted（默认档）

def test_unrestricted_is_the_default_mode() -> None:
    assert Settings.from_env({}).policy_mode == "unrestricted"
    policy = engine()
    for name in ("sudo", "rm", "dd", "bash", "sh", "xargs", "systemctl", "mount"):
        decision = policy.evaluate(name, f"/usr/bin/{name}")
        assert decision.allowed is True, (name, decision)
        assert decision.matched_rule == "unrestricted"
        assert decision.reason is None


def test_unrestricted_ignores_command_dir_restriction() -> None:
    policy = engine()
    decision = policy.evaluate("ls", "/tmp/evil/ls", allowed_dirs=("/usr/bin", "/bin"))
    assert decision.allowed is True
    assert decision.matched_rule == "unrestricted"


def test_unrestricted_operator_denylist_still_applies() -> None:
    policy = engine(LCMD_DENYLIST="reboot,shutdown")
    for name in ("reboot", "shutdown"):
        decision = policy.evaluate(name, f"/usr/sbin/{name}")
        assert decision.allowed is False
        assert decision.category == "operator_deny"
    assert policy.effective_denylist == frozenset({"reboot", "shutdown"})


def test_unrestricted_env_allows_arbitrary_keys() -> None:
    policy = engine()
    env = policy.build_env(os.environ, {"LD_PRELOAD": "/tmp/e.so", "PATH": "/tmp/evil", "MY_FLAG": "1"})
    assert env["LD_PRELOAD"] == "/tmp/e.so"
    assert env["PATH"] == "/tmp/evil"
    assert env["MY_FLAG"] == "1"


def test_unrestricted_env_still_validates_shape() -> None:
    policy = engine()
    with pytest.raises(ToolFailure) as exc:
        policy.build_env(os.environ, {"1BAD": "x"})
    assert exc.value.code is ErrorCode.ENV_KEY_FORBIDDEN
    with pytest.raises(ToolFailure) as exc:
        policy.build_env(os.environ, {"GOOD": "a\x00b"})
    assert exc.value.code is ErrorCode.ENV_VALUE_INVALID
    with pytest.raises(ToolFailure) as exc:
        policy.build_env(os.environ, {"GOOD": 1})  # type: ignore[dict-item]
    assert exc.value.code is ErrorCode.ENV_VALUE_INVALID
