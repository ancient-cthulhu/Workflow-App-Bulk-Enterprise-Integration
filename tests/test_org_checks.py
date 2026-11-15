"""GitHub org checks: installation pagination, Actions policy matching."""
import json

import pytest

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


def test_installations_paginated(monkeypatch):
    calls = []

    def req(method, url, token, **kw):
        calls.append(url)
        if "page=2" in url:
            return R(200, {"installations": [{"app_slug": script.APP_SLUG, "id": 9}]})
        return R(200, {"total_count": 101, "installations": [{"app_slug": f"other{i}"} for i in range(100)]},
                 headers={"Link": f'<{url}?page=2>; rel="next"'})

    monkeypatch.setattr(script, "request", req)
    assert script.find_app_installation("https://api.github.com", "o", "t", script.APP_SLUG)["id"] == 9
    assert len(calls) == 2


def test_installations_error_raises(monkeypatch):
    monkeypatch.setattr(script, "request", lambda *a, **k: R(403, {}))
    with pytest.raises(RuntimeError, match="cannot list installations"):
        script.list_org_installations("https://api.github.com", "o", "t")


def _allow(monkeypatch, body, enabled="all", repos=None):
    def req(method, url, token, **kw):
        if url.endswith("/actions/permissions"):
            return R(200, {"enabled_repositories": enabled, "allowed_actions": "selected"})
        if url.endswith("/actions/permissions/repositories"):
            return R(200, {"total_count": len(repos or []), "repositories": repos or []})
        return R(200, body)

    monkeypatch.setattr(script, "request", req)
    return script.check_actions_allowlist("https://api.github.com", "o", "t")


def test_owner_wildcards_cover_required_actions(monkeypatch):
    res = _allow(monkeypatch, {"github_owned_allowed": True, "verified_allowed": False,
                               "patterns_allowed": ["veracode/*", "android-actions/*",
                                                    "flutter-actions/*", "octokit/*"]})
    assert res["status"] == "selected_ok" and res["missing"] == []


def test_case_insensitive_and_unversioned_and_pinned(monkeypatch):
    pats = [p.lower() for p in script._REQUIRED_ACTION_PATTERNS if not p.startswith("actions/")]
    pats = [p.replace("@*", "") if "sca" in p else p for p in pats]          # owner/repo
    pats = [p.replace("@*", "@v1") if "flaws" in p else p for p in pats]     # owner/repo@ref
    res = _allow(monkeypatch, {"github_owned_allowed": True, "patterns_allowed": pats})
    assert res["status"] == "selected_ok"


def test_unrelated_patterns_still_missing(monkeypatch):
    res = _allow(monkeypatch, {"github_owned_allowed": False,
                               "patterns_allowed": ["veracode/veracode-sca@*", "veracod/*", "octokit/other@*"]})
    assert res["status"] == "selected_missing"
    assert "veracode/veracode-sca@*" not in res["missing"]
    assert "octokit/request-action@*" in res["missing"]
    assert "actions/checkout@*" in res["missing"]


def test_actions_disabled_for_org(monkeypatch):
    monkeypatch.setattr(script, "request",
                        lambda *a, **k: R(200, {"enabled_repositories": "none", "allowed_actions": "all"}))
    assert script.check_actions_allowlist("https://api.github.com", "o", "t")["status"] == "actions_disabled"


def test_selected_repos_without_veracode(monkeypatch):
    def req(method, url, token, **kw):
        if url.endswith("/actions/permissions"):
            return R(200, {"enabled_repositories": "selected", "allowed_actions": "all"})
        return R(200, {"total_count": 1, "repositories": [{"name": "other"}]})

    monkeypatch.setattr(script, "request", req)
    assert script.check_actions_allowlist("https://api.github.com", "o", "t")["status"] == "repo_not_enabled"


def test_selected_repos_with_veracode_on_page_two(monkeypatch):
    def req(method, url, token, **kw):
        if url.endswith("/actions/permissions"):
            return R(200, {"enabled_repositories": "selected", "allowed_actions": "all"})
        if "page=2" in url:
            return R(200, {"repositories": [{"name": "veracode"}]})
        return R(200, {"total_count": 101, "repositories": [{"name": f"r{i}"} for i in range(100)]},
                 headers={"Link": f'<{url}?page=2>; rel="next"'})

    monkeypatch.setattr(script, "request", req)
    assert script.check_actions_allowlist("https://api.github.com", "o", "t")["status"] == "all_allowed"
