"""Repo bootstrap safety: --fix-repos re-import and git push behaviour."""
import json
import os
import shutil
import subprocess

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


def _health(monkeypatch, workflow_status):
    def req(method, url, token, **kw):
        if url.endswith("/repos/o/veracode"):
            return R(200, {"default_branch": "main"})
        if url.endswith("/commits"):
            return R(200, [{"sha": "x"}])
        if "/contents/.github/workflows/" in url:
            return R(workflow_status, {})
        return R(200, {"sha": "s", "content": ""})

    calls = []
    monkeypatch.setattr(script, "request", req)
    monkeypatch.setattr(script, "check_git_available", lambda: True)
    monkeypatch.setattr(script, "git_mirror_import",
                        lambda *a, **k: (calls.append((a, k)), (True, "ok"))[1])
    monkeypatch.setattr(script, "wait_for_main_branch", lambda *a, **k: True)
    res = script.check_repo_health("https://api.github.com", "o", "veracode", "t", None, None, None,
                                   dry_run=False, log=lambda *_: None)
    return res, calls


@pytest.mark.parametrize("status", [502, 403, 500])
def test_fix_repos_does_not_reimport_when_workflow_check_is_not_404(monkeypatch, status):
    res, calls = _health(monkeypatch, status)
    assert calls == []
    assert res.reimport_action == f"unknown:workflow_check_{status}"


def test_fix_repos_reimport_into_existing_repo_never_mirrors(monkeypatch):
    res, calls = _health(monkeypatch, 404)
    assert res.reimport_action == "reimported"
    assert len(calls) == 1 and calls[0][1].get("mirror") is False


class _Proc:
    def __init__(self, rc=0, stderr=""):
        self.returncode = rc
        self.stderr = stderr


def test_non_mirror_push_only_pushes_main_without_force(monkeypatch, tmp_path):
    cmds = []

    def fake_run(cmd, **kw):
        cmds.append(cmd)
        return _Proc()

    monkeypatch.setattr(script.subprocess, "run", fake_run)
    ok, _ = script.git_mirror_import("https://github.com/veracode/x", "org", "veracode", "T", mirror=False)
    assert ok
    push = cmds[-1]
    assert "--mirror" not in push and "--force" not in push and "-f" not in push
    assert push[-2:] == ["https://github.com/org/veracode.git", "refs/heads/main:refs/heads/main"]


def test_non_mirror_push_rejection_is_reported(monkeypatch):
    def fake_run(cmd, **kw):
        if "push" in cmd:
            return _Proc(1, " ! [rejected]        main -> main (non-fast-forward)")
        return _Proc()

    monkeypatch.setattr(script.subprocess, "run", fake_run)
    ok, msg = script.git_mirror_import("https://github.com/veracode/x", "org", "veracode", "T", mirror=False)
    assert not ok and "rejected" in msg.lower() and "not forc" in msg.lower()


def test_push_from_cached_clone_without_copy(monkeypatch, tmp_path):
    (tmp_path / "repo.git").mkdir()
    cmds = []
    monkeypatch.setattr(script.subprocess, "run", lambda cmd, **kw: (cmds.append(cmd), _Proc())[1])
    monkeypatch.setattr(script.shutil, "copytree", lambda *a, **k: pytest.fail("copytree called"))
    ok, _ = script.git_mirror_import("u", "org", "veracode", "T", cached_clone_dir=str(tmp_path))
    assert ok and len(cmds) == 1
    assert cmds[0][2] == os.path.join(str(tmp_path), "repo.git")
    assert (tmp_path / "repo.git").is_dir()  # cache left intact for other orgs


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_non_mirror_push_keeps_customer_branches(monkeypatch, tmp_path):
    def g(*a, cwd=tmp_path):
        subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True)

    up, tgt, work = tmp_path / "up", tmp_path / "tgt.git", tmp_path / "work"
    g("init", "-q", "-b", "main", str(up))
    g("-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "--allow-empty", "-m", "u", cwd=up)
    g("init", "-q", "--bare", str(tgt))
    g("init", "-q", "-b", "custom", str(work))
    g("-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "--allow-empty", "-m", "c", cwd=work)
    g("push", "-q", str(tgt), "custom", cwd=work)
    cache = tmp_path / "cache"
    cache.mkdir()
    g("clone", "-q", "--bare", str(up), str(cache / "repo.git"))

    real_run = subprocess.run

    def run(cmd, **kw):  # redirect the https target URL to the local bare repo
        cmd = [str(tgt) if c == "https://github.com/org/veracode.git" else c for c in cmd]
        return real_run(cmd, **kw)

    monkeypatch.setattr(script.subprocess, "run", run)
    ok, msg = script.git_mirror_import("u", "org", "veracode", "T", cached_clone_dir=str(cache), mirror=False)
    assert ok, msg
    refs = real_run(["git", "for-each-ref", "--format=%(refname)"], cwd=tgt,
                    capture_output=True, text=True).stdout.split()
    assert "refs/heads/custom" in refs and "refs/heads/main" in refs


def test_branch_check_error_is_not_branch_not_found(monkeypatch):
    monkeypatch.setattr(script, "request", lambda m, url, t, **k: R(502, {}))
    ok, action = script.set_default_branch("https://api.github.com", "o", "veracode", "t",
                                           log=lambda *_: None, current_branch="master")
    assert not ok and action == "failed"
