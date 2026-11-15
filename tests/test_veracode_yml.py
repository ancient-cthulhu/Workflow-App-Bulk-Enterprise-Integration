"""veracode.yml update with default-veracode.yml backup. All GitHub I/O is faked."""
import json
from base64 import b64decode, b64encode

import pytest

import script

VY, BK = "veracode.yml", "default-veracode.yml"


class Resp:
    def __init__(self, status=200, data=None):
        self.status_code, self._d, self.headers = status, data, {}
        self.text = json.dumps(data)

    def json(self):
        return self._d


class FakeRepo:
    def __init__(self, files: dict[str, str], backup_put_status: int = 201, backup_get_status: int | None = None):
        self.files = {k: (f"sha-{k}", v) for k, v in files.items()}
        self.puts: list[tuple[str, str | None]] = []
        self.backup_put_status = backup_put_status
        self.backup_get_status = backup_get_status

    def __call__(self, method, url, token, *a, **kw):
        name = url.rsplit("/", 1)[-1]
        if method == "GET":
            if name == BK and self.backup_get_status is not None:
                return Resp(self.backup_get_status, {})
            if name in self.files:
                sha, c = self.files[name]
                return Resp(200, {"sha": sha, "content": b64encode(c.encode()).decode()})
            return Resp(404, {})
        self.puts.append((name, kw["json"].get("sha")))
        if name == BK and self.backup_put_status not in (200, 201):
            return Resp(self.backup_put_status, {"message": "nope"})
        self.files[name] = (f"sha{len(self.puts)}", b64decode(kw["json"]["content"]).decode())
        return Resp(201, {})


def put(monkeypatch, repo, content):
    monkeypatch.setattr(script, "request", repo)
    return script._put_veracode_yml_with_backup("https://api.x", "o", "veracode", "t", content)


def test_backup_written_once_and_never_clobbered(monkeypatch):
    repo = FakeRepo({VY: "customer: original\n"})
    assert put(monkeypatch, repo, "bulk: v1\n") == (True, "updated_with_backup")
    assert repo.files[BK][1] == "customer: original\n"
    assert put(monkeypatch, repo, "bulk: v2\n") == (True, "updated_with_backup")
    assert repo.files[BK][1] == "customer: original\n"  # still the customer's original
    assert repo.files[VY][1] == "bulk: v2\n"
    assert [n for n, _ in repo.puts] == [BK, VY, VY]


@pytest.mark.parametrize("status", [403, 409, 422, 500])
def test_backup_failure_aborts_update(monkeypatch, status):
    repo = FakeRepo({VY: "customer: original\n"}, backup_put_status=status)
    assert put(monkeypatch, repo, "bulk: v1\n") == (False, f"backup_failed:{status}")
    assert repo.files[VY][1] == "customer: original\n"
    assert [n for n, _ in repo.puts] == [BK]


def test_backup_lookup_error_aborts_update(monkeypatch):
    repo = FakeRepo({VY: "customer: original\n"}, backup_get_status=500)
    assert put(monkeypatch, repo, "bulk: v1\n") == (False, "backup_failed:500")
    assert repo.puts == []


@pytest.mark.parametrize("current", ["bulk: v1\n", "bulk: v1\r\n"])
def test_identical_content_writes_nothing(monkeypatch, current):
    repo = FakeRepo({VY: current})
    assert put(monkeypatch, repo, "bulk: v1\n") == (True, "already_current")
    assert repo.puts == []


def test_create_when_missing(monkeypatch):
    repo = FakeRepo({})
    assert put(monkeypatch, repo, "bulk: v1\n") == (True, "created")
    assert [n for n, _ in repo.puts] == [VY]


@pytest.mark.parametrize("bad", ["a: [\n", "- just\n- a list\n", "x: 1\n\tbad: tab\n"])
def test_invalid_template_is_never_put(monkeypatch, bad):
    repo = FakeRepo({VY: "customer: original\n"})
    assert put(monkeypatch, repo, bad) == (False, "invalid_yaml")
    assert repo.puts == []
