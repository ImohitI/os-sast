import urllib.error

from os_sast.llm import LLMError
from os_sast.model import Finding
from os_sast.triage import RESPONSE_SCHEMA, code_snippet, parse_verdict, triage


class FakeProvider:
    name, model, sends_code_off_machine = "fake", "m", False

    def __init__(self, answer=None, error=None):
        self.answer, self.error, self.calls = answer, error, []

    def complete_json(self, prompt, schema):
        self.calls.append((prompt, schema))
        if self.error:
            raise self.error
        return self.answer


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


def test_triage_never_removes_findings_even_when_the_model_is_down(tmp_path):
    (tmp_path / "app.py").write_text("a\nb\nc\n")
    findings = [make_finding(1), make_finding(2)]
    triage(findings, str(tmp_path), FakeProvider(error=urllib.error.URLError("connection refused")))
    assert len(findings) == 2
    assert all(f.ai is None for f in findings)


def test_triage_survives_provider_errors_too(tmp_path):
    (tmp_path / "app.py").write_text("a\nb\nc\n")
    findings = [make_finding()]
    triage(findings, str(tmp_path), FakeProvider(error=LLMError("refused")))
    assert len(findings) == 1 and findings[0].ai is None


def test_triage_annotates_likely_fp_but_keeps_it(tmp_path):
    (tmp_path / "app.py").write_text("a\nb\nc\n")
    provider = FakeProvider('{"verdict": "likely_fp", "confidence": 0.9, "reason": "constant", "suggestedFix": ""}')
    findings = [make_finding()]
    triage(findings, str(tmp_path), provider)
    assert len(findings) == 1
    assert findings[0].ai["verdict"] == "likely_fp"
    prompt, schema = provider.calls[0]
    assert ">>    2 | b" in prompt and schema is RESPONSE_SCHEMA


def test_schema_is_strict_enough_for_openai():
    assert RESPONSE_SCHEMA["additionalProperties"] is False
    assert set(RESPONSE_SCHEMA["required"]) == set(RESPONSE_SCHEMA["properties"])
