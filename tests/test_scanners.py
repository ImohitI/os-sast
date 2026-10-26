import shutil

import pytest

from os_sast.scanners import BUNDLED_RULES, parse_bandit, parse_opengrep, run_opengrep

OPENGREP = {
    "version": "1.32.0",
    "results": [
        {
            "check_id": "python-sqli",
            "path": "python/app.py",
            "start": {"line": 20},
            "extra": {
                "severity": "ERROR",
                "message": "User input flows into SQL\n",
                "metadata": {"cwe": ["CWE-89: Improper Neutralization of ... ('SQL Injection')"]},
            },
        },
        {
            "check_id": "generic.no-cwe",
            "path": "./js/server.js",
            "start": {"line": 3},
            "extra": {"severity": "INFO", "message": "m", "metadata": {}},
        },
    ],
}

BANDIT = {
    "results": [
        {
            "filename": "./python/app.py",
            "line_number": 34,
            "issue_severity": "HIGH",
            "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
            "issue_text": "subprocess call with shell=True identified",
            "test_id": "B602",
            "test_name": "subprocess_popen_with_shell_equals_true",
        }
    ]
}


def test_opengrep_maps_severity_cwe_and_path():
    first, second = parse_opengrep(OPENGREP, "/repo")
    assert first.tool == "opengrep"
    assert first.cwe == "CWE-89"
    assert first.severity == "HIGH"
    assert first.file == "python/app.py"
    assert first.message == "User input flows into SQL"
    assert second.cwe is None
    assert second.severity == "LOW"
    assert second.file == "js/server.js"


def test_bandit_paths_match_opengrep_paths():
    (finding,) = parse_bandit(BANDIT, "/repo")
    assert finding.file == "python/app.py"  # "./python/app.py" normalized, so fingerprints agree
    assert finding.cwe == "CWE-78"
    assert finding.rule_id == "bandit.B602.subprocess_popen_with_shell_equals_true"
    assert finding.severity == "HIGH"


def test_rules_are_bundled_one_file_per_cwe():
    assert sorted(p.name for p in BUNDLED_RULES.glob("*.yaml")) == [
        "command-injection.yaml", "path-traversal.yaml", "sql-injection.yaml", "weak-hash.yaml", "xss.yaml"]


@pytest.mark.skipif(shutil.which("opengrep") is None, reason="opengrep binary not installed")
def test_bundled_rules_report_clean_rule_ids_and_relative_paths(tmp_path):
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "api.py").write_text(
        "import subprocess\n"
        "from flask import request\n"
        "def run():\n"
        "    subprocess.call('ls ' + request.args.get('d'), shell=True)\n"
        "def safe():\n"
        "    subprocess.call(['ls', request.args.get('d')])\n"
    )
    findings, version = run_opengrep(str(tmp_path))
    assert [(f.rule_id, f.file, f.line, f.cwe) for f in findings] == [
        ("python-command-injection", "web/api.py", 4, "CWE-78")]  # no local path prefix, argument list not flagged
    assert version
