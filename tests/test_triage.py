import urllib.error

from os_sast import triage as triage_module
from os_sast.model import Finding
from os_sast.triage import code_snippet, parse_verdict, triage


def make_finding(line=2):
    return Finding(fingerprint="f" * 64, cwe="CWE-89", rule_id="r", found_by=["opengrep"],
                   severity="HIGH", file="app.py", line=line, message="m")


def test_parse_verdict_accepts_valid_json_and_clamps_confidence():
    ai = parse_verdict('{"verdict": "likely_tp", "confidence": 1.7, "reason": "tainted", "suggestedFix": ""}')
    assert ai == {"verdict": "likely_tp", "confidence": 1.0, "reason": "tainted", "suggestedFix": None}


def test_parse_verdict_rejects_unknown_verdicts_and_garbage():
    assert parse_verdict('{"verdict": "maybe", "confidence": 0.5}') is None
    assert parse_verdict("not json") is None
    assert parse_verdict('{"verdict": "likely_fp", "confidence": "high"}') is None


def test_snippet_marks_the_flagged_line(tmp_path):
    (tmp_path / "app.py").write_text("a = 1\nquery = f'{x}'\nrun(query)\n")
    snippet = code_snippet(str(tmp_path), "app.py", 2, context=1)
    assert snippet.splitlines() == ["      1 | a = 1", ">>    2 | query = f'{x}'", "      3 | run(query)"]


def test_triage_never_removes_findings_even_when_the_model_is_down(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("a\nb\nc\n")

    def unreachable(*args, **kwargs):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(triage_module, "ask_ollama", unreachable)
    findings = [make_finding(1), make_finding(2)]
    triage(findings, str(tmp_path), "http://localhost:11434", "m")
    assert len(findings) == 2
    assert all(f.ai is None for f in findings)


def test_triage_annotates_likely_fp_but_keeps_it(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("a\nb\nc\n")
    monkeypatch.setattr(triage_module, "ask_ollama",
                        lambda *a, **k: '{"verdict": "likely_fp", "confidence": 0.9, "reason": "constant", "suggestedFix": ""}')
    findings = [make_finding()]
    triage(findings, str(tmp_path), "http://localhost:11434", "m")
    assert len(findings) == 1
    assert findings[0].ai["verdict"] == "likely_fp"
