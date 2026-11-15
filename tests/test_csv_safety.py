"""CSV reports must not be interpreted as formulas by spreadsheet apps."""
import csv

import pytest

import script

DANGEROUS = ["=HYPERLINK(\"http://e\",\"x\")", "+1", "-2+3", "@SUM(A1)", "\tx", "\rx"]


def read(p):
    with p.open(encoding="utf-8", newline="") as f:
        return list(csv.reader(f))


@pytest.mark.parametrize("cell", DANGEROUS)
def test_write_csv_neutralizes_formulas(tmp_path, cell):
    p = tmp_path / "x.csv"
    script.write_csv(p, ["organization", "note"], [[cell, "ok"]])
    rows = read(p)
    assert rows[1] == ["'" + cell, "ok"]


def test_write_csv_leaves_safe_cells_and_non_strings(tmp_path):
    p = tmp_path / "x.csv"
    script.write_csv(p, ["a", "b", "c"], [["org-1", 5, "a=b"]])
    assert read(p)[1] == ["org-1", "5", "a=b"]


def test_teams_map_neutralizes_formulas(tmp_path):
    p = tmp_path / "teams_map.csv"
    script.write_teams_map_csv(p, ["good-org", "=cmd"])
    assert read(p) == [["org", "teams"], ["good-org", ""], ["'=cmd", ""]]
