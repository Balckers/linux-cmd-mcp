"""配置层测试：超时上限/默认值耦合、HTTP/鉴权字段、默认目录开关。"""

from __future__ import annotations

import pytest

from linux_cmd_mcp.config import Settings
from linux_cmd_mcp.errors import ConfigError


def test_defaults_are_ssh_level_and_sse() -> None:
    settings = Settings.from_env({})
    assert settings.policy_mode == "unrestricted"
    assert settings.http_host == "127.0.0.1"
    assert settings.http_port == 8765
    assert settings.include_default_dirs is True
    assert settings.auth_token is None
    assert settings.is_loopback_bind is True
    assert settings.auth_required is False


def test_tightening_max_timeout_clamps_default(monkeypatch_env=None) -> None:
    """只收紧上限时默认值跟着夹到上限，不能因此让服务器起不来。"""
    settings = Settings.from_env({"LCMD_MAX_TIMEOUT_SECONDS": "10"})
    assert settings.max_timeout_seconds == 10
    assert settings.default_timeout_seconds == 10


def test_explicit_conflicting_default_timeout_fails_loudly() -> None:
    with pytest.raises(ConfigError) as exc:
        Settings.from_env({"LCMD_MAX_TIMEOUT_SECONDS": "10", "LCMD_DEFAULT_TIMEOUT_SECONDS": "20"})
    assert "LCMD_DEFAULT_TIMEOUT_SECONDS" in str(exc.value)


@pytest.mark.parametrize(
    ("env", "field", "expected"),
    [
        ({"LCMD_HTTP_HOST": "0.0.0.0"}, "http_host", "0.0.0.0"),
        ({"LCMD_HTTP_PORT": "9100"}, "http_port", 9100),
        ({"LCMD_INCLUDE_DEFAULT_DIRS": "0"}, "include_default_dirs", False),
    ],
)
def test_http_fields_parse(env: dict[str, str], field: str, expected: object) -> None:
    assert getattr(Settings.from_env(env), field) == expected


def test_bad_values_fail_loudly() -> None:
    for env in (
        {"LCMD_POLICY_MODE": "yolo"},
        {"LCMD_HTTP_PORT": "70000"},
        {"LCMD_AUTH_TOKEN": "short"},
        {"LCMD_POLICY_MODE": "strict", "LCMD_ALLOWLIST": "git", "LCMD_DENYLIST": "git"},
    ):
        with pytest.raises(ConfigError):
            Settings.from_env(env)


def test_http_summary_never_echoes_token() -> None:
    token = "0123456789abcdef0123456789abcdef"
    settings = Settings.from_env({"LCMD_AUTH_TOKEN": token})
    summary = settings.http_summary()
    assert summary["auth_enabled"] is True
    assert token not in str(summary)
    assert settings.auth_required is True


def test_allowed_hosts_parse_and_wildcard() -> None:
    settings = Settings.from_env({"LCMD_ALLOWED_HOSTS": "nas.example.com:*,ops.example.com"})
    assert settings.allowed_hosts == ("nas.example.com:*", "ops.example.com")

    wildcard = Settings.from_env({"LCMD_ALLOWED_HOSTS": "*"})
    assert wildcard.allowed_hosts == ("*",)

    with pytest.raises(ConfigError):
        Settings.from_env({"LCMD_ALLOWED_HOSTS": "https://nas.example.com/sse"})


def test_http_summary_reports_allowed_hosts_without_token() -> None:
    token = "0123456789abcdef0123456789abcdef"
    settings = Settings.from_env({"LCMD_AUTH_TOKEN": token, "LCMD_ALLOWED_HOSTS": "nas.example.com:*"})
    summary = settings.http_summary()
    assert summary["allowed_hosts"] == ["nas.example.com:*"]
    assert token not in str(summary)


def test_empty_path_override_is_respected() -> None:
    """显式设置 LCMD_PATH='' 表示不搜索 PATH，而不是悄悄回退到进程 PATH。"""
    settings = Settings.from_env({"LCMD_PATH": ""})
    assert settings.path_env == ""
    assert settings.effective_path_env() == ""


def test_missing_path_override_uses_process_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", "/probe/bin")
    settings = Settings.from_env({})
    assert settings.path_env is None
    assert settings.effective_path_env() == "/probe/bin"
