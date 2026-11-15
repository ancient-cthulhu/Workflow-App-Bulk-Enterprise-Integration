"""Secrets: key before token rotation, visibility, no token leaks, cheap status."""
import base64
import json
import time as _real_time
from typing import Any

import pytest

import script


class R:
    def __init__(self, status=200, body=None, headers=None, text=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        self.text = text if text is not None else (json.dumps(body) if body is not None else "")
        self.content = self.text.encode()

    def json(self):
        return self._body


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    slept = []

    class NoSleepTime:
        time = staticmethod(_real_time.time)
        sleep = staticmethod(slept.append)
        strftime = staticmethod(_real_time.strftime)
        localtime = staticmethod(_real_time.localtime)

    monkeypatch.setattr(script, "time", NoSleepTime)
    return slept


@pytest.fixture
def pk():
    from nacl import public
    return base64.b64encode(bytes(public.PrivateKey.generate().public_key)).decode()


def _ctx(tmp_path, **kw):
    base: dict[str, Any] = dict(
        api_base="https://api.github.com", web_base="https://github.com", token="t",
        do_apply_repo=False, do_set_secrets=True, do_set_teams=False, do_update_yml=False,
        do_create_teams=False, do_fix_repos=False, do_link_teams=False, dry_run=False,
        teams_mode="none", yml_content=None, onboarding_yml_content=None, teams_map={},
        team_prefix="", veracode_api_id="vid", veracode_api_key="vkey",
        veracode_sa_api_id="said", veracode_sa_api_key="sakey", total_orgs=1,
        report_path=tmp_path / "r.json", checkpoint_file=tmp_path / "cp.json",
    )
    base.update(kw)
    return script.RunContext(**base)


def _stub_org_checks(monkeypatch):
    monkeypatch.setattr(script, "check_app_installed", lambda *a, **k: (True, {}))
    monkeypatch.setattr(script, "check_actions_allowlist", lambda *a, **k: {"status": "all_allowed"})
    monkeypatch.setattr(script, "create_veracode_workspace", lambda *a, **k: "WS")
    entries = []
    monkeypatch.setattr(script, "append_report_entry", lambda path, e: entries.append(e))
    return entries


def test_token_not_rotated_when_public_key_unavailable(monkeypatch, tmp_path):
    entries = _stub_org_checks(monkeypatch)
    rotated = []
    monkeypatch.setattr(script, "get_org_public_key", lambda *a, **k: None)
    monkeypatch.setattr(script, "create_veracode_agent_token", lambda *a, **k: rotated.append(1) or "NEW")
    script.process_org("o", 1, _ctx(tmp_path), buf=script.OrgBuffer("o", 1, 1, flush_on_add=False))
    assert rotated == []
    assert entries[0]["secrets"]["status"] == "error"
    assert "not rotated" in entries[0]["secrets"]["error"]


def test_key_fetched_once_and_reused(monkeypatch, tmp_path, pk):
    _stub_org_checks(monkeypatch)
    order = []
    monkeypatch.setattr(script, "get_org_public_key", lambda *a, **k: order.append("key") or ("K", pk))
    monkeypatch.setattr(script, "create_veracode_agent_token", lambda *a, **k: order.append("token") or "NEW")

    def req(method, url, token, **kw):
        if method == "GET" and url.endswith("/repos/o/veracode"):
            return R(200, {"id": 42})
        return R(201, {})

    monkeypatch.setattr(script, "request", req)
    ctx = _ctx(tmp_path)
    script.process_org("o", 1, ctx, buf=script.OrgBuffer("o", 1, 1, flush_on_add=False))
    assert order == ["key", "token"]
    assert ctx.stats.secrets_success == 1


def _secret_puts(monkeypatch, pk, repo_resp, visibility):
    calls = []

    def req(method, url, token, **kw):
        calls.append((method, url, kw.get("json")))
        if url.endswith("public-key"):
            return R(200, {"key_id": "K", "key": pk})
        if url.endswith("/repos/o/veracode"):
            return repo_resp
        return R(201, {})

    monkeypatch.setattr(script, "request", req)
    ok, res = script.set_veracode_secrets("https://api.github.com", "o", "t", "a", "b", "c",
                                          log=lambda *_: None, visibility=visibility)
    return ok, res, calls


def test_default_visibility_is_selected_veracode_repo(monkeypatch, pk, no_sleep):
    ok, res, calls = _secret_puts(monkeypatch, pk, R(200, {"id": 42}), "selected")
    puts = [c[2] for c in calls if c[0] == "PUT"]
    assert ok and len(puts) == 3
    assert all(p["visibility"] == "selected" and p["selected_repository_ids"] == [42] for p in puts)
    # no per-secret verification GETs and no sleeps
    gets = [c for c in calls if c[0] == "GET"]
    assert len(gets) == 2 and no_sleep == []
    assert set(res.values()) == {"set"}


def test_selected_falls_back_to_private_without_repo(monkeypatch, pk):
    ok, _, calls = _secret_puts(monkeypatch, pk, R(404, {}), "selected")
    puts = [c[2] for c in calls if c[0] == "PUT"]
    assert ok and all(p["visibility"] == "private" and "selected_repository_ids" not in p for p in puts)


@pytest.mark.parametrize("vis", ["private", "all"])
def test_explicit_visibility(monkeypatch, pk, vis):
    _, _, calls = _secret_puts(monkeypatch, pk, R(200, {"id": 42}), vis)
    assert all(c[2]["visibility"] == vis for c in calls if c[0] == "PUT")
    assert not any(c[1].endswith("/repos/o/veracode") for c in calls)


def test_secret_visibility_flag_default():
    import inspect
    assert "--secret-visibility" in inspect.getsource(script.main)
    assert script.RunContext.__dataclass_fields__["secret_visibility"].default == "selected"


# ---------------------------------------------------------------- agent token
SECRET = "s3cr3t-token-value"


@pytest.mark.parametrize("body", [{"access_token": SECRET}, {"token": {"access_token": SECRET}}])
def test_agent_create_accepts_both_token_shapes(monkeypatch, body):
    def vr(method, endpoint, *a, **k):
        if method == "GET":
            return R(200, {"_embedded": {"agents": []}, "page": {"total_pages": 1}})
        return R(200, body)

    monkeypatch.setattr(script, "veracode_request", vr)
    assert script.create_veracode_agent_token("WS", "myorg", "id", "key", log=lambda *_: None) == SECRET


@pytest.mark.parametrize("status,body", [
    (200, {"id": "A1", "token": {"refresh_token": SECRET}}),  # no access_token -> keys only
    (500, {"error": SECRET}),                                  # failure -> status only
])
def test_agent_create_never_logs_body(monkeypatch, status, body):
    def vr(method, endpoint, *a, **k):
        if method == "GET":
            return R(200, {"_embedded": {"agents": []}, "page": {"total_pages": 1}})
        return R(status, body)

    monkeypatch.setattr(script, "veracode_request", vr)
    logs = []
    assert script.create_veracode_agent_token("WS", "myorg", "id", "key", log=logs.append) is None
    assert logs and not any(SECRET in line for line in logs)
    if status == 200:
        assert any("['id', 'token']" in line for line in logs)


def test_agent_regenerate_failure_never_logs_body(monkeypatch):
    def vr(method, endpoint, *a, **k):
        if method == "GET":
            return R(200, {"_embedded": {"agents": [{"name": "myorg-agt", "id": "A1"}]}, "page": {"total_pages": 1}})
        return R(400, {"leak": SECRET})

    monkeypatch.setattr(script, "veracode_request", vr)
    logs = []
    assert script.create_veracode_agent_token("WS", "myorg", "id", "key", log=logs.append) is None
    assert not any(SECRET in line for line in logs)


# ---------------------------------------------------------------- dry-run status
def test_dry_run_status_single_paginated_list(monkeypatch):
    calls = []

    def req(method, url, token, params=None, **kw):
        calls.append(url)
        if "page=2" in url:
            return R(200, {"secrets": [{"name": "VERACODE_AGENT_TOKEN"}]})
        return R(200, {"total_count": 101, "secrets": [{"name": "VERACODE_API_ID"}]},
                 headers={"Link": '<https://api.github.com/orgs/o/actions/secrets?page=2>; rel="next"'})

    monkeypatch.setattr(script, "request", req)
    res = script.check_veracode_secrets_status("https://api.github.com", "o", "t")
    assert res == {"VERACODE_API_ID": "exists", "VERACODE_API_KEY": "missing", "VERACODE_AGENT_TOKEN": "exists"}
    assert len(calls) == 2


def test_dry_run_status_no_permission(monkeypatch):
    monkeypatch.setattr(script, "request", lambda *a, **k: R(403, {}))
    assert set(script.check_veracode_secrets_status("https://api.github.com", "o", "t").values()) == {"no_permission"}
