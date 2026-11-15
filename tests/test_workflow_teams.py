"""Teams injection into the upstream policy/sandbox scan workflows.

Fixtures under tests/fixtures/ are the workflow files of
veracode/github-actions-integration @ dca8f11. Every timing probe runs in a
child process with a hard 10s timeout, so a regression fails instead of hanging.
"""
import json
import subprocess
import sys
import textwrap
from base64 import b64decode, b64encode
from pathlib import Path

import pytest
import yaml

import script

ROOT = Path(__file__).resolve().parents[1]
FIX = Path(__file__).parent / "fixtures"
POL = ".github/workflows/veracode-policy-scan.yml"
SBX = ".github/workflows/veracode-sandbox-scan.yml"


def fx(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")  # universal newlines -> LF


def src_for(path: str) -> str:
    return fx(path.rsplit("/", 1)[-1])


def uas_with(text: str) -> dict:
    d = yaml.safe_load(text)
    for job in d["jobs"].values():
        for st in job.get("steps", []) or []:
            if "uploadandscan" in str(st.get("uses", "")):
                return st["with"]
    raise AssertionError("uploadandscan step not found")


# --------------------------------------------------------------------------- #
# ReDoS: the step must be located by walking lines, not by a backtracking regex
# --------------------------------------------------------------------------- #
_CHILD = textwrap.dedent("""
    import sys, time
    sys.path.insert(0, sys.argv[1])
    import script
    content = open(sys.argv[2], encoding="utf-8", newline="").read()
    t = time.perf_counter()
    out, changed, action = script._apply_teams_to_workflow(sys.argv[3], content, "A", True)
    print(f"{time.perf_counter() - t:.4f} {changed} {action}")
""")


def _timed_child(tmp_path, content: str, path: str = POL) -> tuple[float, str]:
    f = tmp_path / "wf.yml"
    f.write_bytes(content.encode("utf-8"))
    try:
        p = subprocess.run([sys.executable, "-c", _CHILD, str(ROOT), str(f), path],
                           capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        raise AssertionError("teams injection did not finish within 10s (catastrophic backtracking)") from None
    assert p.returncode == 0, p.stderr[-500:]
    secs, rest = p.stdout.split(" ", 1)
    return float(secs), rest.strip()


def _synthetic_step(eol: str, with_line: str, n: int = 15) -> str:
    params = "".join(f"          p{i}: value-{i}{eol}" for i in range(n))
    return (f"jobs:{eol}  j:{eol}    steps:{eol}      - name: s{eol}"
            f"        uses: veracode/uploadandscan-action@v0.2.3{eol}        id: x{eol}"
            f"        {with_line}{eol}{params}")


def test_real_upstream_policy_scan_crlf_is_fast(tmp_path):
    secs, result = _timed_child(tmp_path, src_for(POL).replace("\n", "\r\n"))
    assert secs < 1.0
    assert result == "True teams_updated"


@pytest.mark.parametrize("eol,with_line", [("\r\n", "with:"), ("\n", "with:  # inputs"), ("\n", "with: ")])
def test_with_line_variants_are_fast_and_injected(tmp_path, eol, with_line):
    secs, result = _timed_child(tmp_path, _synthetic_step(eol, with_line))
    assert secs < 1.0
    assert result == "True teams_updated"


@pytest.mark.parametrize("eol", ["\n", "\r\n"])
def test_crlf_preserved_and_value_in_with_block(eol):
    src = src_for(POL).replace("\n", eol)
    out, changed, action = script._apply_teams_to_workflow(POL, src, "Team A", True)
    assert (changed, action) == (True, "teams_updated")
    assert uas_with(out)["teams"] == "Team A"
    if eol == "\r\n":
        assert "\n" not in out.replace("\r\n", "")


def test_with_trailing_comment_injects_into_step():
    src = src_for(POL).replace("        with:\n          appname:", "        with:  # inputs\n          appname:", 1)
    assert src != src_for(POL)
    out, changed, _ = script._apply_teams_to_workflow(POL, src, "A", True)
    assert changed and uas_with(out)["teams"] == "A"
    assert "with:  # inputs" in out


# --------------------------------------------------------------------------- #
# Escaping / YAML validity
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("team", ["Team A", 'Te"am', "a: b", "x # y", "A, B", "Ünïcödé", "it's",
                                  "*star", "@at", "back\\slash", "trailing\\", "a\\b"])
@pytest.mark.parametrize("path", [POL, SBX])
def test_inject_roundtrips_exact_value(team, path):
    src = src_for(path)
    out, changed, action = script._apply_teams_to_workflow(path, src, team, True)
    assert (changed, action) == (True, "teams_updated")
    assert uas_with(out)["teams"] == team
    assert [ln for ln in out.splitlines() if "teams:" not in ln] == src.splitlines()
    # idempotent
    assert script._apply_teams_to_workflow(path, out, team, True)[1:] == (False, "already_current")


@pytest.mark.parametrize("existing", ["teams: 'Old'  # owner", 'teams: "It\'s"', "teams: Old # c",
                                      'teams: "a\\\\b"', "teams:", "teams: ''"])
def test_existing_scalar_teams_updated(existing):
    src = src_for(POL).replace("          createprofile: true\n", f"          createprofile: true\n          {existing}\n")
    out, changed, action = script._apply_teams_to_workflow(POL, src, "New", True)
    assert (changed, action) == (True, "teams_updated")
    assert uas_with(out)["teams"] == "New"


def test_existing_teams_with_comment_already_current_keeps_comment():
    src = src_for(POL).replace("          createprofile: true\n", "          createprofile: true\n          teams: 'New'  # owner\n")
    out, changed, action = script._apply_teams_to_workflow(POL, src, "New", True)
    assert (out, changed, action) == (src, False, "already_current")


def test_existing_teams_not_updated_without_update_existing():
    src = src_for(POL).replace("          createprofile: true\n", "          createprofile: true\n          teams: Old\n")
    assert script._apply_teams_to_workflow(POL, src, "New", False) == (src, False, "already_current")


def test_block_sequence_teams_replaced_with_scalar():
    src = src_for(POL).replace("          createprofile: true\n",
                               "          createprofile: true\n          teams:\n            - A\n            - B\n")
    out, changed, action = script._apply_teams_to_workflow(POL, src, "New", True)
    assert (changed, action) == (True, "teams_updated")
    assert uas_with(out)["teams"] == "New"
    assert "- A" not in out


def test_unparseable_teams_reported():
    src = src_for(POL).replace("          createprofile: true\n",
                               "          createprofile: true\n          teams: {a: 1}\n")
    out, changed, action = script._apply_teams_to_workflow(POL, src, "New", True)
    assert (out, changed, action) == (src, False, "unrecognized_teams_value")


def test_update_does_not_touch_unrelated_teams_keys():
    src = src_for(POL).replace("jobs:\n", "env:\n  teams: keepme\njobs:\n", 1)
    out, changed, _ = script._apply_teams_to_workflow(POL, src, "New", True)
    assert changed
    d = yaml.safe_load(out)
    assert d["env"]["teams"] == "keepme"
    assert uas_with(out)["teams"] == "New"


def test_later_step_teams_key_does_not_suppress_injection():
    src = src_for(POL).replace(
        "          debug: ${{ inputs.debug }}\n\n",
        "          debug: ${{ inputs.debug }}\n      - name: other\n        uses: x/y@v1\n"
        "        with:\n          teams: unrelated\n\n", 1)
    assert src != src_for(POL)
    out, changed, _ = script._apply_teams_to_workflow(POL, src, "New", False)
    assert changed and uas_with(out)["teams"] == "New"
    assert "teams: unrelated" in out


def test_invalid_result_is_not_returned(monkeypatch):
    # If an edit ever produced invalid YAML (or changed other keys), nothing is written.
    monkeypatch.setattr(script, "_edit_uploadandscan_teams",
                        lambda content, teams, upd: (content.replace("jobs:", "jobs: [", 1), True, "teams_updated"))
    src = src_for(POL)
    assert script._apply_teams_to_workflow(POL, src, "A", True) == (src, False, "invalid_yaml")
    monkeypatch.setattr(script, "_edit_uploadandscan_teams",
                        lambda content, teams, upd: (content.replace("createprofile: true", "createprofile: false"),
                                                     True, "teams_updated"))
    assert script._apply_teams_to_workflow(POL, src, "A", True) == (src, False, "invalid_yaml")


# --------------------------------------------------------------------------- #
# inject_teams_into_workflows: what actually gets PUT
# --------------------------------------------------------------------------- #
class Resp:
    def __init__(self, status=200, data=None):
        self.status_code, self._d, self.headers = status, data, {}
        self.text = json.dumps(data)

    def json(self):
        return self._d


def _fake_repo(monkeypatch, files: dict[str, str]):
    puts = []

    def fake(method, url, token, *a, **kw):
        path = url.split("/contents/", 1)[1]
        if method == "GET":
            if path in files:
                return Resp(200, {"sha": "s1", "content": b64encode(files[path].encode()).decode()})
            return Resp(404, {})
        puts.append((path, b64decode(kw["json"]["content"]).decode()))
        return Resp(200, {})
    monkeypatch.setattr(script, "request", fake)
    return puts


def test_put_content_is_valid_yaml_with_exact_value(monkeypatch):
    puts = _fake_repo(monkeypatch, {POL: src_for(POL), SBX: src_for(SBX)})
    ok, msg = script.inject_teams_into_workflows("https://api.x", "o", "veracode", "t", "dom\\users",
                                                 update_existing=True, log=lambda *_: None)
    assert (ok, msg) == (True, "teams_updated_2_files")
    assert sorted(p for p, _ in puts) == sorted([POL, SBX])
    for _, body in puts:
        assert uas_with(body)["teams"] == "dom\\users"


def test_invalid_edit_is_never_put(monkeypatch):
    puts = _fake_repo(monkeypatch, {POL: src_for(POL)})
    monkeypatch.setattr(script, "_edit_uploadandscan_teams",
                        lambda content, teams, upd: (content.replace("jobs:", "jobs: [", 1), True, "teams_updated"))
    actions: dict[str, str] = {}
    script.inject_teams_into_workflows("https://api.x", "o", "veracode", "t", "A",
                                       update_existing=True, log=lambda *_: None, file_actions=actions)
    assert puts == []
    assert actions["veracode-policy-scan.yml"] == "invalid_yaml"


def test_no_uploadandscan_step_is_reported():
    src = "jobs:\n  j:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          teams: x\n"
    assert script._apply_teams_to_workflow(POL, src, "A", True) == (src, False, "uploadandscan_step_not_found")
