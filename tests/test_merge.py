import hashlib

from os_sast.merge import fingerprint, merge
from os_sast.model import RawFinding


def raw(tool, severity, line=34, cwe="CWE-78", rule="r"):
    return RawFinding(tool=tool, rule_id=f"{tool}.{rule}", cwe=cwe, severity=severity,
                      file="python/app.py", line=line, message=f"{tool} says so")


def test_fingerprint_is_sha256_of_cwe_file_line():
    expected = hashlib.sha256(b"CWE-89|python/app.py|20").hexdigest()
    assert fingerprint("CWE-89", "python/app.py", 20) == expected


def test_same_cwe_file_line_becomes_one_finding_with_both_tools():
    (finding,) = merge([raw("bandit", "HIGH"), raw("opengrep", "MEDIUM"), raw("opengrep", "HIGH", rule="r2")])
    assert finding.found_by == ["bandit", "opengrep"]
    assert finding.severity == "HIGH"
    assert finding.rule_id == "opengrep.r2"  # on a severity tie opengrep's rule id leads


def test_different_line_or_cwe_stays_separate():
    findings = merge([raw("opengrep", "HIGH", line=19), raw("bandit", "HIGH", line=20),
                      raw("opengrep", "HIGH", line=20, cwe="CWE-89")])
    assert len(findings) == 3
    assert [f.line for f in findings] == [19, 20, 20]
