"""--upstream-ref: which upstream veracode.yml --update-veracode-yml (without FILE) pushes."""
import pytest

import script
from test_orchestration import Recorder, run_main


class R:
    def __init__(self, status, text="", data=None):
        self.status_code, self.text, self._d, self.headers = status, text, data, {}

    def json(self):
        return self._d


class FakeSession:
    def __init__(self, routes):
        self.routes, self.urls = routes, []

    def get(self, url, **kw):
        self.urls.append(url)
        for frag, resp in self.routes.items():
            if frag in url:
                return resp
        return R(404, "nope")


def patch_session(monkeypatch, routes):
    s = FakeSession(routes)
    monkeypatch.setattr(script, "_session", lambda: s)
    return s


def test_default_ref_is_latest_release_tag(monkeypatch):
    s = patch_session(monkeypatch, {"/releases/latest": R(200, data={"tag_name": "v1.2.3"})})
    assert script.resolve_upstream_ref(None) == "v1.2.3"
    assert s.urls == ["https://api.github.com/repos/veracode/github-actions-integration/releases/latest"]


@pytest.mark.parametrize("ref", ["main", "v0.2.11", "release/1.0"])
def test_explicit_ref_needs_no_lookup(monkeypatch, ref):
    s = patch_session(monkeypatch, {})
    assert script.resolve_upstream_ref(ref) == ref
    assert s.urls == []


@pytest.mark.parametrize("ref", ["../x", "a b", "v1;rm", "-x"])
def test_invalid_ref_rejected(monkeypatch, ref):
    patch_session(monkeypatch, {})
    assert script.resolve_upstream_ref(ref) is None


def test_latest_release_lookup_failure_returns_none(monkeypatch):
    patch_session(monkeypatch, {"/releases/latest": R(404, "{}", {})})
    assert script.resolve_upstream_ref(None) is None


def test_fetch_uses_ref(monkeypatch):
    s = patch_session(monkeypatch, {"/v1.2.3/veracode.yml": R(200, "a: 1\n")})
    assert script.fetch_upstream_veracode_yml("v1.2.3") == "a: 1\n"
    assert s.urls == ["https://raw.githubusercontent.com/veracode/github-actions-integration/v1.2.3/veracode.yml"]


def test_main_pushes_latest_release_yml_by_default(monkeypatch, tmp_path):
    s = patch_session(monkeypatch, {"/releases/latest": R(200, data={"tag_name": "v9.9.9"}),
                                    "/v9.9.9/veracode.yml": R(200, "pinned: true\n")})
    rec = Recorder()
    code = run_main(monkeypatch, tmp_path, ["--apply", "--yes", "--update-veracode-yml"], rec)
    assert code == 0
    assert any(u.endswith("/v9.9.9/veracode.yml") for u in s.urls)
    assert not any("/main/veracode.yml" in u for u in s.urls)
    assert any(w[2].endswith("/contents/veracode.yml") for w in rec.writes)


def test_main_upstream_ref_main_is_allowed(monkeypatch, tmp_path):
    s = patch_session(monkeypatch, {"/main/veracode.yml": R(200, "x: 1\n")})
    code = run_main(monkeypatch, tmp_path, ["--apply", "--yes", "--update-veracode-yml", "--upstream-ref", "main"],
                    Recorder())
    assert code == 0
    assert s.urls == ["https://raw.githubusercontent.com/veracode/github-actions-integration/main/veracode.yml"]
