"""validate_credentials: SA creds, Identity API admin probe, PAT scope warnings."""
import json

import script


class R:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        self.text = json.dumps(body) if body is not None else ""
        self.content = self.text.encode()

    def json(self):
        return self._body


def _gh_ok(scopes="admin:org, repo, workflow"):
    return lambda *a, **k: R(200, {"login": "me"}, headers={"X-OAuth-Scopes": scopes})


def _vc(routes):
    """routes: {(api_id, endpoint): status}; default 200."""
    calls = []

    def vr(method, endpoint, api_id, api_key, **kw):
        calls.append((api_id, endpoint))
        return R(routes.get((api_id, endpoint), 200), {})
    return vr, calls


def test_invalid_sa_credentials_fail_validation(monkeypatch):
    monkeypatch.setattr(script, "request", _gh_ok())
    vr, calls = _vc({("sa", "/api/authn/v2/users/self"): 401})
    monkeypatch.setattr(script, "veracode_request", vr)
    ok, errors = script.validate_credentials("https://api.github.com", "t", "vid", "vkey", True,
                                             veracode_sa_api_id="sa", veracode_sa_api_key="sk")
    assert not ok and any("VERACODE_SA_API" in e for e in errors)
    assert ("sa", "/api/authn/v2/users/self") in calls


def test_sa_forbidden_probe_is_only_a_warning(monkeypatch, capsys):
    monkeypatch.setattr(script, "request", _gh_ok())
    vr, _ = _vc({("sa", "/api/authn/v2/users/self"): 403})
    monkeypatch.setattr(script, "veracode_request", vr)
    ok, _ = script.validate_credentials("https://api.github.com", "t", "vid", "vkey", True,
                                        veracode_sa_api_id="sa", veracode_sa_api_key="sk")
    assert ok and "[WARN]" in capsys.readouterr().out


def test_create_teams_requires_identity_admin(monkeypatch):
    monkeypatch.setattr(script, "request", _gh_ok())
    vr, calls = _vc({("vid", "/api/authn/v2/teams"): 403})
    monkeypatch.setattr(script, "veracode_request", vr)
    ok, errors = script.validate_credentials("https://api.github.com", "t", "vid", "vkey", True,
                                             check_teams_api=True)
    assert not ok and any("Administrator" in e for e in errors)


def test_teams_probe_skipped_without_create_teams(monkeypatch):
    monkeypatch.setattr(script, "request", _gh_ok())
    vr, calls = _vc({})
    monkeypatch.setattr(script, "veracode_request", vr)
    assert script.validate_credentials("https://api.github.com", "t", "vid", "vkey", True)[0]
    assert [c[1] for c in calls] == ["/srcclr/v3/workspaces"]


def test_missing_pat_scopes_warned(monkeypatch, capsys):
    monkeypatch.setattr(script, "request", _gh_ok("repo, read:org"))
    req = script.required_github_scopes(enterprise=True, writes_workflows=True)
    ok, _ = script.validate_credentials("https://api.github.com", "t", None, None, False, required_scopes=req)
    out = capsys.readouterr().out
    assert ok
    for scope in ("admin:org", "workflow", "read:enterprise"):
        assert f"lacks the '{scope}' scope" in out
    assert "lacks the 'repo' scope" not in out


def test_scope_implications():
    req = script.required_github_scopes(enterprise=True, writes_workflows=False)
    assert script.missing_github_scopes("admin:org, repo, admin:enterprise", req) == []
    assert "workflow" not in req
