from os_sast.evaluate import evaluate, score

EXPECTED = [
    {"file": "a.py", "line": 10, "cwe": "CWE-89", "isVulnerable": True},
    {"file": "a.py", "line": 30, "cwe": "CWE-78", "isVulnerable": True},
    {"file": "a.py", "line": 50, "cwe": "CWE-89", "isVulnerable": False},
]


def finding(line, cwe="CWE-89", ai=None):
    return {"file": "a.py", "line": line, "cwe": cwe, "ai": ai}


def test_line_tolerance_and_cwe_must_match():
    s = score([finding(12), finding(10, cwe="CWE-79")], EXPECTED, tolerance=2)
    assert s.true_positives == 1
    assert s.bugs_found == 1


def test_bait_and_noise_both_hurt_precision():
    s = score([finding(10), finding(50), finding(99)], EXPECTED, tolerance=2)
    assert s.precision == 1 / 3
    assert s.bait_flagged == 1
    assert s.recall == 0.5
    assert [b["line"] for b in s.missed] == [30]


def test_two_findings_on_one_bug_count_once_for_recall():
    s = score([finding(9), finding(10)], EXPECTED, tolerance=2)
    assert s.true_positives == 2
    assert s.bugs_found == 1


def test_ai_report_shows_real_bugs_called_false_positive():
    fp = {"verdict": "likely_fp", "confidence": 0.8, "reason": "looks constant"}
    tp = {"verdict": "likely_tp", "confidence": 0.9, "reason": "tainted"}
    result = {"findings": [finding(10, ai=fp), finding(30, cwe="CWE-78", ai=tp), finding(50, ai=fp)]}
    report = evaluate(result, {"entries": EXPECTED}, tolerance=2)
    assert "hide likely_fp" in report
    assert "1 real bug finding(s) called likely_fp" in report
    assert "a.py:10 CWE-89 (looks constant)" in report
