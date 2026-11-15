"""Veracode lookups: error vs not-found, pagination, per-run team cache."""
import json
import time as _real_time

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
    class NoSleepTime:
        time = staticmethod(_real_time.time)
        sleep = staticmethod(lambda *_: None)
        strftime = staticmethod(_real_time.strftime)
        localtime = staticmethod(_real_time.localtime)

    monkeypatch.setattr(script, "time", NoSleepTime)


def _quiet(*_):
    return None


@pytest.mark.parametrize("status", [401, 403, 500])
def test_workspace_lookup_error_never_posts(monkeypatch, status):
    calls = []

    def vr(method, endpoint, *a, **k):
        calls.append(method)
        return R(status, {}, text="boom") if method == "GET" else R(201, {})

    monkeypatch.setattr(script, "veracode_request", vr)
    assert script.create_veracode_workspace("myorg", "id", "key", log=_quiet) is None
    assert "POST" not in calls


def test_workspace_not_found_then_created(monkeypatch):
    gets = iter([
        R(200, {"_embedded": {"workspaces": []}, "page": {"total_pages": 1}}),
        R(200, {"_embedded": {"workspaces": [{"name": "myorg", "id": "WS"}]}, "page": {"total_pages": 1}}),
    ])
    monkeypatch.setattr(script, "veracode_request",
                        lambda m, e, *a, **k: next(gets) if m == "GET" else R(201, {}))
    assert script.create_veracode_workspace("myorg", "id", "key", log=_quiet) == "WS"


@pytest.mark.parametrize("status", [403, 502])
def test_team_lookup_error_never_posts(monkeypatch, status):
    calls = []

    def vr(method, endpoint, *a, **k):
        calls.append(method)
        return R(status, {}) if method == "GET" else R(201, {"team_id": "NEW"})

    monkeypatch.setattr(script, "veracode_request", vr)
    assert script.ensure_veracode_team("t", "id", "key", log=_quiet) == (None, "error")
    assert "POST" not in calls


def test_link_workspace_lookup_error_is_error_not_missing(monkeypatch):
    monkeypatch.setattr(script, "veracode_request", lambda *a, **k: R(500, {}))
    assert script.ensure_team_linked_to_workspace("o", "t", "id", "key", log=_quiet) == (False, "error")


def _paged(key, pages):
    def vr(method, endpoint, *a, params=None, **k):
        p = (params or {}).get("page", 0)
        return R(200, {"_embedded": {key: pages[p]}, "page": {"total_pages": len(pages)}})
    return vr


def test_list_agents_paginates(monkeypatch):
    pages = [[{"name": f"a{i}", "id": i} for i in range(100)], [{"name": "myorg-agt", "id": "A1"}]]
    monkeypatch.setattr(script, "veracode_request", _paged("agents", pages))
    agents = script.list_veracode_agents("WS", "id", "key")
    assert len(agents) == 101 and agents[-1]["id"] == "A1"


def test_workspace_has_team_paginates(monkeypatch):
    pages = [[{"id": i} for i in range(100)], [{"id": 777}]]
    monkeypatch.setattr(script, "veracode_request", _paged("teams", pages))
    assert script._workspace_has_team("WS", "777", "id", "key", log=_quiet) is True


def test_teams_listed_once_per_run(monkeypatch):
    calls = []

    def vr(method, endpoint, *a, params=None, **k):
        calls.append(method)
        if method == "GET":
            return R(200, {"_embedded": {"teams": [{"team_name": f"t{params['page']}", "team_id": "x"}]},
                           "page": {"total_pages": 20}})
        return R(201, {"team_id": "NEW"})

    monkeypatch.setattr(script, "veracode_request", vr)
    assert script.ensure_veracode_team("absent", "id", "key", log=_quiet) == ("NEW", "created")
    assert calls.count("GET") == 20
    # Second org: same and other team names resolve from the cache, no re-scan.
    assert script.ensure_veracode_team("absent", "id", "key", log=_quiet) == ("NEW", "already_exists")
    assert script.ensure_veracode_team("t7", "id", "key", log=_quiet) == ("x", "already_exists")
    assert calls.count("GET") == 20 and calls.count("POST") == 1


def test_team_409_refreshes_cache(monkeypatch):
    lists = iter([
        R(200, {"_embedded": {"teams": []}, "page": {"total_pages": 1}}),
        R(200, {"_embedded": {"teams": [{"team_name": "t", "team_id": "TID"}]}, "page": {"total_pages": 1}}),
    ])
    monkeypatch.setattr(script, "veracode_request",
                        lambda m, e, *a, **k: next(lists) if m == "GET" else R(409, {}))
    assert script.ensure_veracode_team("t", "id", "key", log=_quiet) == ("TID", "created")
