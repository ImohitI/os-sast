"""os-sast output must match the ScanResult contract owned by sast-platform.

tests/contract/scan-result.schema.json is a copy of sast-platform/contracts/src/main/resources/scan-result.schema.json.
When both repos are checked out side by side, the drift test fails if the copy is stale.
"""

import json
from pathlib import Path

import jsonschema
import pytest

from os_sast import cli
from os_sast.model import RawFinding

SCHEMA_PATH = Path(__file__).parent / "contract" / "scan-result.schema.json"
PLATFORM_SCHEMA = (Path(__file__).parents[2] / "sast-platform" / "contracts" / "src" / "main"
                   / "resources" / "scan-result.schema.json")


def fake_opengrep(root, config):
    return [RawFinding("opengrep", "rule.sqli", "CWE-89", "HIGH", "app.py", 2, "sqli")], "1.0.0"


def fake_bandit(root):
    return [RawFinding("bandit", "bandit.B608.sql", "CWE-89", "MEDIUM", "app.py", 2, "sql"),
            RawFinding("bandit", "bandit.B404.blacklist", None, "LOW", "app.py", 1, "import")], "1.9.0"


def test_scan_output_matches_the_contract(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("import subprocess\nrun(q)\n")
    monkeypatch.setattr(cli, "run_opengrep", fake_opengrep)
    monkeypatch.setattr(cli, "run_bandit", fake_bandit)
    out = tmp_path / "result.json"

    assert cli.main(["scan", str(tmp_path), "--repo", "samples", "--build", "7", "--commit", "abc", "--out", str(out)]) == 0

    result = json.loads(out.read_text())
    jsonschema.validate(result, json.loads(SCHEMA_PATH.read_text()))
    assert result["buildId"] == 7
    assert [f["foundBy"] for f in result["findings"]] == [["bandit"], ["bandit", "opengrep"]]


@pytest.mark.skipif(not PLATFORM_SCHEMA.exists(), reason="sast-platform not checked out next to os-sast")
def test_vendored_schema_is_in_step_with_sast_platform():
    assert json.loads(SCHEMA_PATH.read_text()) == json.loads(PLATFORM_SCHEMA.read_text())
