"""HTTP retry core: non-idempotent POSTs, idempotent creates, rate-limit waits."""
import json
import time as _real_time

import pytest
import requests

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


class FakeSession:
    def __init__(self, script_):
        self.script = list(script_)
        self.calls = []

    def request(self, method, url, **kw):
        self.calls.append((method, url))
        nxt = self.script.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    slept = []

    class NoSleepTime:
        time = staticmethod(_real_time.time)
        sleep = staticmethod(slept.append)
        strftime = staticmethod(_real_time.strftime)
        localtime = staticmethod(_real_time.localtime)

    monkeypatch.setattr(script, "time", NoSleepTime)
    monkeypatch.setattr(script, "_veracode_auth", lambda *a: None)
    return slept


def test_post_not_retried_after_read_timeout(monkeypatch):
    sess = FakeSession([requests.exceptions.ReadTimeout("maybe applied"), R(201, {})])
    monkeypatch.setattr(script, "_session", lambda: sess)
    with pytest.raises(requests.exceptions.ReadTimeout):
        script.request("POST", "https://api.github.com/orgs/o/repos", "t", json={})
    assert [c[0] for c in sess.calls] == ["POST"]


def test_post_retried_after_connect_timeout(monkeypatch):
    sess = FakeSession([requests.exceptions.ConnectTimeout("never sent"), R(201, {})])
    monkeypatch.setattr(script, "_session", lambda: sess)
    assert script.request("POST", "https://api.github.com/orgs/o/repos", "t", json={}).status_code == 201


def test_put_and_get_still_retried_after_read_timeout(monkeypatch):
    for method in ("GET", "PUT"):
        sess = FakeSession([requests.exceptions.ReadTimeout("x"), R(200, {})])
        monkeypatch.setattr(script, "_session", lambda: sess)
        assert script.request(method, "https://api.github.com/x", "t").status_code == 200
        assert len(sess.calls) == 2


def test_veracode_post_not_retried_after_read_timeout(monkeypatch):
    sess = FakeSession([requests.exceptions.ReadTimeout("x"), R(200, {})])
    monkeypatch.setattr(script, "_session", lambda: sess)
    with pytest.raises(requests.exceptions.ReadTimeout):
        script.veracode_request("POST", "/srcclr/v3/workspaces", "id", "key", json={})
    assert len(sess.calls) == 1


def test_create_repo_already_exists_is_success(monkeypatch):
    sess = FakeSession([R(422, {"message": "Repository creation failed.",
                                "errors": [{"field": "name", "message": "name already exists on this account"}]})])
    monkeypatch.setattr(script, "_session", lambda: sess)
    script.create_repo("https://api.github.com", "o", "veracode", "t")  # no raise


def test_create_repo_timeout_then_exists_is_success(monkeypatch):
    sess = FakeSession([requests.exceptions.ReadTimeout("applied"), R(200, {"name": "veracode"})])
    monkeypatch.setattr(script, "_session", lambda: sess)
    script.create_repo("https://api.github.com", "o", "veracode", "t")
    assert [c[0] for c in sess.calls] == ["POST", "GET"]


def test_create_repo_other_422_still_raises(monkeypatch):
    sess = FakeSession([R(422, {"message": "Visibility can't be private"})])
    monkeypatch.setattr(script, "_session", lambda: sess)
    with pytest.raises(RuntimeError, match="repo create failed 422"):
        script.create_repo("https://api.github.com", "o", "veracode", "t")


def test_workspace_post_timeout_resolves_by_lookup(monkeypatch):
    sess = FakeSession([
        R(200, {"_embedded": {"workspaces": []}, "page": {"total_pages": 1}}),
        requests.exceptions.ReadTimeout("server applied it"),
        R(200, {"_embedded": {"workspaces": [{"name": "myorg", "id": "WS1"}]}, "page": {"total_pages": 1}}),
    ])
    monkeypatch.setattr(script, "_session", lambda: sess)
    assert script.create_veracode_workspace("myorg", "id", "key", log=lambda *_: None) == "WS1"
    assert [c[0] for c in sess.calls] == ["GET", "POST", "GET"]


@pytest.mark.parametrize("status", [409, 422])
def test_workspace_conflict_resolves_by_lookup(monkeypatch, status):
    sess = FakeSession([
        R(200, {"_embedded": {"workspaces": []}, "page": {"total_pages": 1}}),
        R(status, {}, text="workspace already exists"),
        R(200, {"_embedded": {"workspaces": [{"name": "myorg", "id": "WS1"}]}, "page": {"total_pages": 1}}),
    ])
    monkeypatch.setattr(script, "_session", lambda: sess)
    assert script.create_veracode_workspace("myorg", "id", "key", log=lambda *_: None) == "WS1"


def test_primary_exhaustion_no_double_sleep(monkeypatch):
    clock = {"t": 1_000_000.0}
    slept = []

    class FakeTime:
        @staticmethod
        def time():
            return clock["t"]

        @staticmethod
        def sleep(x):
            slept.append(x)
            clock["t"] += x

        strftime = staticmethod(_real_time.strftime)
        localtime = staticmethod(_real_time.localtime)

    monkeypatch.setattr(script, "time", FakeTime)
    reset = int(clock["t"]) + 100
    sess = FakeSession([
        R(403, {}, text="API rate limit exceeded",
          headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(reset)}),
        R(200, {}, headers={}),
    ])
    monkeypatch.setattr(script, "_session", lambda: sess)
    assert script.request("GET", "https://api.github.com/x", "t").status_code == 200
    # check_rate_limit already slept until reset (+5); no extra 60s floor on top
    assert 100 <= sum(slept) < 100 + 10


def test_team_post_timeout_resolves_by_lookup(monkeypatch):
    sess = FakeSession([
        requests.exceptions.ReadTimeout("applied"),
        R(200, {"_embedded": {"teams": [{"team_name": "t1", "team_id": "TID"}]}, "page": {"total_pages": 1}}),
    ])
    monkeypatch.setattr(script, "_session", lambda: sess)
    assert script.create_veracode_team("t1", "id", "key", log=lambda *_: None) == "TID"
    assert [c[0] for c in sess.calls] == ["POST", "GET"]
