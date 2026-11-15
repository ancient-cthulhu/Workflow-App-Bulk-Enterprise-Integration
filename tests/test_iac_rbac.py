"""IaC/Secrets workflow conversion to the Veracode CLI with RBAC.

Fixtures are veracode/github-actions-integration's veracode-iac-secrets-scan.yml
at dca8f11 and at v0.2.11.
"""
from pathlib import Path

import pytest
import yaml

import script

FIX = Path(__file__).parent / "fixtures"
IAC = script.IAC_WORKFLOW_PATH
RBAC_NAME = "Run Veracode IaC/Secrets Scanning (team RBAC)"


def fx(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def iac_step(text: str) -> dict:
    return next(x for x in yaml.safe_load(text)["jobs"]["veracode-iac-secrets-scan"]["steps"]
                if x.get("id") == "veracode_iac_scan")


@pytest.mark.parametrize("name", ["veracode-iac-secrets-scan.yml", "veracode-iac-secrets-scan.v0.2.11.yml"])
@pytest.mark.parametrize("team", ['Q"uote', "back\\slash", "a: b # c", " A , B ,, ", "Ünï"])
def test_iac_conversion_valid_and_preserving(name, team):
    src = fx(name)
    out, changed, action = script._apply_teams_to_workflow(IAC, src, team, True)
    assert (changed, action) == (True, "converted")
    d, s = yaml.safe_load(out), yaml.safe_load(src)
    assert {k: v for k, v in d.items() if k != "jobs"} == {k: v for k, v in s.items() if k != "jobs"}
    assert {j: v for j, v in d["jobs"].items() if j != "veracode-iac-secrets-scan"} == \
           {j: v for j, v in s["jobs"].items() if j != "veracode-iac-secrets-scan"}
    step = iac_step(out)
    assert step["env"]["VERACODE_TEAMS"] == script.normalize_teams_for_cli(team)
    # Distinct from upstream's step name so Upstream-Sync sees a customised step, not a renamed one.
    assert step["name"] == RBAC_NAME
    assert script._IAC_RBAC_MARKER in out
    assert script._apply_teams_to_workflow(IAC, out, team, True)[1:] == (False, "already_current")


def test_iac_previously_converted_file_with_old_step_name_is_current():
    out, *_ = script.apply_iac_rbac(fx("veracode-iac-secrets-scan.yml"), "A")
    legacy = out.replace(RBAC_NAME, "Run Veracode IaC/Secrets Scanning")
    assert legacy != out
    assert script.apply_iac_rbac(legacy, "A") == (legacy, False, "already_current")


def test_iac_crlf_preserved():
    out, _, action = script.apply_iac_rbac(fx("veracode-iac-secrets-scan.yml").replace("\n", "\r\n"), "T")
    assert action == "converted" and yaml.safe_load(out)
    assert "\n" not in out.replace("\r\n", "")
    out2, changed, action2 = script.apply_iac_rbac(out, "U")
    assert (changed, action2) == (True, "teams_updated")
    assert "\n" not in out2.replace("\r\n", "")
    assert iac_step(out2)["env"]["VERACODE_TEAMS"] == "U"


@pytest.mark.parametrize("line", ['VERACODE_TEAMS: "A"  # owner', "VERACODE_TEAMS: 'A' # owner", "VERACODE_TEAMS: A # owner"])
def test_iac_comment_on_teams_line_is_not_part_of_value(line):
    out, *_ = script.apply_iac_rbac(fx("veracode-iac-secrets-scan.yml"), "A")
    c = out.replace('VERACODE_TEAMS: "A"', line, 1)
    assert script.apply_iac_rbac(c, "A") == (c, False, "already_current")
    o2, changed, action = script.apply_iac_rbac(c, "B")
    assert (changed, action) == (True, "teams_updated") and "# owner" in o2
    assert iac_step(o2)["env"]["VERACODE_TEAMS"] == "B"


@pytest.mark.parametrize("raw,value", [('"a\\\\b"  # c', "a\\b"), ("'it''s' # c", "it's"), ("plain # c", "plain"),
                                       ('"x # y"', "x # y"), ("", "")])
def test_yaml_scalar_value_strips_comment(raw, value):
    assert script._yaml_scalar_value(raw) == value
