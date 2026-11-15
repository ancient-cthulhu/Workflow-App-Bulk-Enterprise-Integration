"""main() orchestration: dry-run write gating, checkpoint/resume, confirmation, exit codes.

All I/O is faked: GitHub/Veracode requests, git subprocesses and org discovery.
"""
import builtins
import json
import subprocess
import sys
from base64 import b64encode
from pathlib import Path

import pytest

import script

FIX = Path(__file__).parent / "fixtures"
POL_B64 = b64encode((FIX / "veracode-policy-scan.yml").read_text(encoding="utf-8").encode()).decode()
ALL_FLAGS = ["--import-repo", "--set-teams-auto", "--create-teams", "--set-secrets",
             "--link-teams-to-workspaces", "--update-veracode-yml", "{yml}"]


class Resp:
    def __init__(self, status=200, data=None):
        self.status_code, self._d, self.headers = status, data, {}
        self.text = json.dumps(data)

    def json(self):
        return self._d


class Recorder:
    """Plausible GitHub/Veracode responses; records every non-GET call and git push."""

    def __init__(self, fail_org=None):
        self.writes = []
        self.fail_org = fail_org

    def gh(self, method, url, token, *a, **kw):
        if self.fail_org and (f"/orgs/{self.fail_org}/" in url or f"/repos/{self.fail_org}/" in url
                              or url.endswith(f"/orgs/{self.fail_org}")):
            raise RuntimeError("HTTP 502")
        if method != "GET" and not kw.get("graphql"):
            self.writes.append(("github", method, url))
            return Resp(201, {"sha": "n"})
        if url.endswith("/veracode"):
            return Resp(200, {"default_branch": "main", "size": 10})
        if url.endswith("/commits"):
            return Resp(200, [{"sha": "c"}])
        if "/contents/" in url:
            return Resp(200, {"sha": "s", "content": POL_B64})
        if url.endswith("/branches/main"):
            return Resp(200, {"name": "main"})
        if url.endswith("/installations"):
            return Resp(200, {"total_count": 0, "installations": []})
        if "public-key" in url:
            return Resp(200, {"key_id": "k", "key": b64encode(b"\0" * 32).decode()})
        return Resp(404, {"message": "Not Found"})

    def vc(self, method, endpoint, *a, **kw):
        if method != "GET":
            self.writes.append(("veracode", method, endpoint))
            return Resp(200, {"team_id": "t", "id": "w", "token": "x"})
        return Resp(200, {"_embedded": {}, "page": {"total_pages": 1}})

    def run(self, cmd, *a, **kw):
        if "push" in cmd:
            self.writes.append(("git", "push", " ".join(map(str, cmd[:4]))))
        if list(cmd[:2]) == ["git", "--version"]:
            return subprocess.CompletedProcess(cmd, 0, "git version 2", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")


def run_main(monkeypatch, tmp_path, argv, rec, orgs=("org1",), answer="yes", prompts=None):
    monkeypatch.setattr(script, "request", rec.gh)
    monkeypatch.setattr(script, "veracode_request", rec.vc)
    monkeypatch.setattr(script.subprocess, "run", rec.run)
    monkeypatch.setattr(script, "list_orgs", lambda *a, **k: list(orgs))
    monkeypatch.setattr(script, "validate_credentials", lambda **k: (True, []))
    monkeypatch.setattr(script, "wait_for_main_branch", lambda *a, **k: True)
    monkeypatch.setattr(script.time, "sleep", lambda *_: None)

    def fake_input(*a):
        if prompts is not None:
            prompts.append(1)
        return answer
    monkeypatch.setattr(builtins, "input", fake_input)
    for v in ("GITHUB_TOKEN", "VERACODE_API_ID", "VERACODE_API_KEY", "VERACODE_SA_API_ID", "VERACODE_SA_API_KEY"):
        monkeypatch.setenv(v, "dummy-not-a-secret")
    yml = tmp_path / "v.yml"
    yml.write_text("x: 1\n")
    argv = [a.replace("{yml}", str(yml)) for a in argv]
    monkeypatch.setattr(sys, "argv", ["script.py", "--out", str(tmp_path / "out"), "--enterprise", "e", *argv])
    with pytest.raises(SystemExit) as ex:
        script.main()
    return ex.value.code


def checkpoint(tmp_path):
    return json.loads((tmp_path / "out" / "checkpoint.json").read_text())


_REAL_PROCESS_ORG = script.process_org


def track(monkeypatch, fail_on=None, exc=KeyboardInterrupt):
    seen = []
    real = _REAL_PROCESS_ORG

    def po(org, *a, **k):
        seen.append(org)
        if org == fail_on:
            raise exc("boom")
        return real(org, *a, **k)
    monkeypatch.setattr(script, "process_org", po)
    return seen


# --------------------------------------------------------------------------- #
# Dry-run gating (permanent regression test) + positive control
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("extra", [[], ["--fix-repos"]])
def test_dry_run_makes_no_writes(monkeypatch, tmp_path, extra):
    rec = Recorder()
    flags = [f for f in ALL_FLAGS if not (extra and f == "--import-repo")]
    code = run_main(monkeypatch, tmp_path, ["--dry-run", *flags, *extra], rec)
    assert rec.writes == []
    assert code == 0


def test_positive_control_apply_does_write(monkeypatch, tmp_path):
    rec = Recorder()
    run_main(monkeypatch, tmp_path, ["--apply", *ALL_FLAGS], rec)
    kinds = {w[0] for w in rec.writes}
    assert {"github", "veracode"} <= kinds, rec.writes


# --------------------------------------------------------------------------- #
# Exit codes and report finalisation
# --------------------------------------------------------------------------- #
def test_exit_code_3_when_steps_fail(monkeypatch, tmp_path):
    rec = Recorder()

    def boom(*a, **k):
        raise RuntimeError("HTTP 500")
    rec.gh = boom
    rec.vc = boom
    code = run_main(monkeypatch, tmp_path, ["--apply", "--set-teams-auto", "--set-secrets",
                                            "--update-veracode-yml", "{yml}"], rec)
    report = json.loads(next((tmp_path / "out").glob("audit_report_*.json")).read_text())
    assert "error" in json.dumps(report)
    assert code == 3
    assert checkpoint(tmp_path)["failed"] == ["org1"]


def test_exit_code_3_when_an_org_raises(monkeypatch, tmp_path):
    seen = track(monkeypatch, fail_on="b", exc=RuntimeError)
    code = run_main(monkeypatch, tmp_path, ["--dry-run"], Recorder(), orgs=("a", "b", "c"))
    assert seen == ["a", "b", "c"]  # the run goes on after the exception
    assert code == 3
    cp = checkpoint(tmp_path)
    assert cp["completed"] == ["a", "c"] and cp["failed"] == ["b"]


def test_interrupt_exits_130_and_finalizes_report(monkeypatch, tmp_path):
    track(monkeypatch, fail_on="c")
    code = run_main(monkeypatch, tmp_path, ["--dry-run"], Recorder(), orgs=("a", "b", "c", "d"))
    assert code == 130
    report = json.loads(next((tmp_path / "out").glob("audit_report_*.json")).read_text())
    assert [e["org"] for e in report] == ["a", "b"]
    assert checkpoint(tmp_path)["completed"] == ["a", "b"]


# --------------------------------------------------------------------------- #
# Checkpoint / --continue
# --------------------------------------------------------------------------- #
def test_resume_keeps_orgs_completed_by_earlier_runs(monkeypatch, tmp_path):
    orgs = ("a", "b", "c", "d")
    track(monkeypatch, fail_on="c")
    assert run_main(monkeypatch, tmp_path, ["--dry-run"], Recorder(), orgs=orgs) == 130
    track(monkeypatch, fail_on="d")
    assert run_main(monkeypatch, tmp_path, ["--dry-run", "--continue"], Recorder(), orgs=orgs) == 130
    assert checkpoint(tmp_path)["completed"] == ["a", "b", "c"]
    seen = track(monkeypatch)
    assert run_main(monkeypatch, tmp_path, ["--dry-run", "--continue"], Recorder(), orgs=orgs) == 0
    assert seen == ["d"]
    assert checkpoint(tmp_path)["completed"] == ["a", "b", "c", "d"]


def test_failed_org_is_retried_on_continue(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, ["--dry-run"], Recorder(fail_org="a"), orgs=("a", "b")) == 3
    cp = checkpoint(tmp_path)
    assert cp["completed"] == ["b"] and cp["failed"] == ["a"]
    seen = track(monkeypatch)
    assert run_main(monkeypatch, tmp_path, ["--dry-run", "--continue"], Recorder(), orgs=("a", "b")) == 0
    assert seen == ["a"]
    cp = checkpoint(tmp_path)
    assert sorted(cp["completed"]) == ["a", "b"] and cp["failed"] == []


def test_dry_run_checkpoint_does_not_poison_apply_continue(monkeypatch, tmp_path):
    run_main(monkeypatch, tmp_path, ["--dry-run"], Recorder(), orgs=("a", "b", "c"))
    assert checkpoint(tmp_path)["mode"] == "dry-run"
    seen, prompts = track(monkeypatch), []
    rec = Recorder()
    code = run_main(monkeypatch, tmp_path, ["--apply", "--continue", "--set-teams-auto"], rec,
                    orgs=("a", "b", "c"), prompts=prompts)
    assert prompts, "a mismatching checkpoint must not skip the confirmation"
    assert seen == ["a", "b", "c"] and rec.writes
    assert code == 0
    assert checkpoint(tmp_path)["mode"] == "apply"


def test_checkpoint_with_other_action_flags_is_ignored(monkeypatch, tmp_path):
    run_main(monkeypatch, tmp_path, ["--apply", "--set-teams-auto"], Recorder(), orgs=("a", "b"))
    seen = track(monkeypatch)
    run_main(monkeypatch, tmp_path, ["--apply", "--continue", "--set-secrets"], Recorder(), orgs=("a", "b"))
    assert seen == ["a", "b"]


def test_continue_without_checkpoint_still_asks_for_confirmation(monkeypatch, tmp_path):
    rec, prompts = Recorder(), []
    code = run_main(monkeypatch, tmp_path, ["--apply", "--continue", "--set-teams-auto"], rec,
                    answer="NO", prompts=prompts)
    assert prompts and rec.writes == []
    assert code == 0


def test_continue_with_matching_checkpoint_skips_confirmation(monkeypatch, tmp_path):
    run_main(monkeypatch, tmp_path, ["--apply", "--set-teams-auto"], Recorder(), orgs=("a", "b"))
    seen, prompts = track(monkeypatch), []
    code = run_main(monkeypatch, tmp_path, ["--apply", "--continue", "--set-teams-auto"], Recorder(),
                    orgs=("a", "b", "c"), answer="NO", prompts=prompts)
    assert prompts == [] and seen == ["c"]
    assert code == 0


def test_yes_flag_skips_confirmation(monkeypatch, tmp_path):
    rec, prompts = Recorder(), []
    run_main(monkeypatch, tmp_path, ["--apply", "--yes", "--set-teams-auto"], rec, answer="NO", prompts=prompts)
    assert prompts == [] and rec.writes


def test_checkpoint_written_atomically(monkeypatch, tmp_path):
    replaced = []
    real = script.os.replace

    def spy(src, dst):
        replaced.append(Path(dst).name)
        return real(src, dst)
    monkeypatch.setattr(script.os, "replace", spy)
    run_main(monkeypatch, tmp_path, ["--dry-run"], Recorder(), orgs=("a", "b"))
    assert replaced.count("checkpoint.json") == 2
    assert not list((tmp_path / "out").glob("checkpoint.json.*"))
