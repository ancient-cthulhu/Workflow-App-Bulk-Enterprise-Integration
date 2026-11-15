"""GraphQL enterprise discovery: HTTP 200 RATE_LIMITED is waited out, not 'bad slug'."""
import json
import time as _real_time

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


RATE_LIMITED = {"data": None, "errors": [{"type": "RATE_LIMITED",
                                          "message": "API rate limit exceeded for user ID 1."}]}


def _page(logins, cursor=None, more=False):
    return {"data": {"enterprise": {"organizations": {
        "totalCount": 3, "nodes": [{"login": x} for x in logins],
        "pageInfo": {"hasNextPage": more, "endCursor": cursor}}}}}


@pytest.fixture
def clock(monkeypatch):
    state = {"t": 1_000_000.0, "slept": []}

    class FakeTime:
        @staticmethod
        def time():
            return state["t"]

        @staticmethod
        def sleep(x):
            state["slept"].append(x)
            state["t"] += x

        strftime = staticmethod(_real_time.strftime)
        localtime = staticmethod(_real_time.localtime)

    monkeypatch.setattr(script, "time", FakeTime)
    return state


def test_rate_limited_page_waits_for_reset_and_retries_same_cursor(monkeypatch, clock):
    reset = int(clock["t"]) + 120
    responses = iter([
        R(200, _page(["a", "b"], cursor="C1", more=True)),
        R(200, RATE_LIMITED, headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(reset)}),
        R(200, _page(["c"])),
    ])
    sent = []

    def req(method, url, token, json=None, **kw):
        sent.append(json["variables"].get("cursor"))
        return next(responses)

    monkeypatch.setattr(script, "request", req)
    assert script.list_orgs_graphql("https://api.github.com", "t", "ent") == ["a", "b", "c"]
    assert sent == [None, "C1", "C1"]
    assert 120 <= sum(clock["slept"]) <= 120 + 10


def test_remaining_zero_without_data_is_rate_limit(monkeypatch, clock):
    responses = iter([
        R(200, {"data": None, "errors": [{"message": "limit"}]}, headers={"X-RateLimit-Remaining": "0"}),
        R(200, _page(["a"])),
    ])
    monkeypatch.setattr(script, "request", lambda *a, **k: next(responses))
    assert script.list_orgs_graphql("https://api.github.com", "t", "ent") == ["a"]


def test_persistent_rate_limit_raises_not_bad_slug(monkeypatch, clock):
    monkeypatch.setattr(script, "request", lambda *a, **k: R(200, RATE_LIMITED))
    with pytest.raises(script.OrgDiscoveryError, match="rate limit"):
        script.list_orgs_graphql("https://api.github.com", "t", "ent")


def test_not_found_still_returns_none(monkeypatch, clock):
    body = {"data": {"enterprise": None}, "errors": [{"type": "NOT_FOUND", "message": "no ent"}]}
    monkeypatch.setattr(script, "request", lambda *a, **k: R(200, body))
    assert script.list_orgs_graphql("https://api.github.com", "t", "ent") is None
