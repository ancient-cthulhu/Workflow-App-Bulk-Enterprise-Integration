import base64
import subprocess

import pytest

import script


@pytest.mark.parametrize("api_id, base", [
    ("abcdef0123", "https://api.veracode.com"),
    ("vera01gs-abcdef0123", "https://api.veracode.com"),
    ("vera01ei-abcdef0123", "https://api.veracode.eu"),
    ("VERA01EI-abcdef0123", "https://api.veracode.eu"),
])
def test_veracode_api_base_by_region(api_id, base, monkeypatch):
    monkeypatch.delenv("VERACODE_API_BASE", raising=False)
    assert script.veracode_api_base(api_id) == base


def test_veracode_api_base_override(monkeypatch):
    monkeypatch.setenv("VERACODE_API_BASE", "https://example.test/")
    assert script.veracode_api_base("vera01ei-x") == "https://example.test"


def test_veracode_api_base_rejects_fedramp(monkeypatch):
    monkeypatch.delenv("VERACODE_API_BASE", raising=False)
    with pytest.raises(RuntimeError, match="FedRAMP"):
        script.veracode_api_base("vera01fs-abc")


def test_git_push_env_keeps_token_out_of_argv_and_scopes_header(monkeypatch):
    monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)
    env = script._git_push_env("ghe.example.com", "tok123")
    # The token must not be a plain value anywhere: only base64 inside the header.
    assert not any("tok123" in v for v in env.values() if isinstance(v, str))
    out = subprocess.run(
        ["git", "config", "--get-all", "http.https://ghe.example.com/.extraheader"],
        env=env, capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    assert out[-1] == "Authorization: Basic " + base64.b64encode(b"x-access-token:tok123").decode()


def test_git_push_env_appends_to_existing_git_config_count(monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "user.name")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "x")
    env = script._git_push_env("github.com", "t")
    assert env["GIT_CONFIG_COUNT"] == "4"
    assert env["GIT_CONFIG_KEY_0"] == "user.name"


def test_git_mirror_import_push_has_no_token_in_argv(monkeypatch, tmp_path):
    calls = []

    class R:
        returncode = 0
        stderr = ""

    def fake_run(cmd, **kw):
        calls.append((cmd, kw))
        if cmd[:3] == ["git", "clone", "--bare"]:
            (tmp_path / "x").mkdir(exist_ok=True)
        return R()

    monkeypatch.setattr(script.subprocess, "run", fake_run)
    ok, _ = script.git_mirror_import("https://github.com/veracode/x", "org", "veracode", "SECRET-TOKEN")
    assert ok
    push_cmd, push_kw = calls[-1]
    assert "push" in push_cmd
    assert not any("SECRET-TOKEN" in part for part in push_cmd)
    assert "credential.helper=cache" not in push_cmd
    assert push_cmd[-1] == "https://github.com/org/veracode.git"
