"""Ask an LLM for a verdict on each finding (provider: see llm.py; default a local Ollama model).

The AI only annotates. A finding is never removed here, whatever the verdict: a wrong "likely_fp"
must not hide a real vulnerability. If the model is unreachable or answers nonsense, the finding
keeps ai = None and the scan carries on.
"""

import json
import os
import sys
import urllib.error

from .llm import LLMError
from .model import Finding

CONTEXT_LINES = 15

# Structured output: every provider constrains the model to this JSON shape. All properties are
# required and additionalProperties is false, which OpenAI's strict mode needs.
RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["likely_tp", "likely_fp"]},
        "confidence": {"type": "number"},
        "reason": {"type": "string"},
        "suggestedFix": {"type": "string"},
    },
    "required": ["verdict", "confidence", "reason", "suggestedFix"],
    "additionalProperties": False,
}

PROMPT = """You are an application security reviewer triaging static analysis findings.
Decide if this finding is a real, exploitable vulnerability (likely_tp) or a false positive (likely_fp).
Judge only from the code shown. Untrusted input reaching a dangerous sink without validation, encoding or
parameterization is likely_tp. Safe APIs, constant values or proper sanitization make it likely_fp.

Rule: {rule_id}
CWE: {cwe}
Scanner message: {message}
File: {file}, flagged line marked with >>

{snippet}

Answer as JSON: verdict ("likely_tp" or "likely_fp"), confidence (0 to 1), reason (one sentence),
suggestedFix (one short sentence, or "" if none is needed)."""


def code_snippet(root: str, file: str, line: int, context: int = CONTEXT_LINES) -> str:
    with open(os.path.join(root, file), encoding="utf-8", errors="replace") as handle:
        lines = handle.read().splitlines()
    start, end = max(1, line - context), min(len(lines), line + context)
    return "\n".join(
        f"{'>>' if n == line else '  '} {n:4d} | {lines[n - 1]}" for n in range(start, end + 1)
    )


def build_prompt(finding: Finding, snippet: str) -> str:
    return PROMPT.format(
        rule_id=finding.rule_id, cwe=finding.cwe or "unknown", message=finding.message,
        file=finding.file, snippet=snippet,
    )


def parse_verdict(text: str) -> dict | None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or data.get("verdict") not in ("likely_tp", "likely_fp"):
        return None
    try:
        confidence = min(1.0, max(0.0, float(data.get("confidence", 0))))
    except (TypeError, ValueError):
        return None
    return {
        "verdict": data["verdict"],
        "confidence": round(confidence, 2),
        "reason": str(data.get("reason") or "") or None,
        "suggestedFix": str(data.get("suggestedFix") or "") or None,
    }


def triage(findings: list[Finding], root: str, provider) -> None:
    """Fill finding.ai in place using provider.complete_json. Never removes or reorders findings."""
    for index, finding in enumerate(findings, start=1):
        try:
            prompt = build_prompt(finding, code_snippet(root, finding.file, finding.line))
            finding.ai = parse_verdict(provider.complete_json(prompt, RESPONSE_SCHEMA))
        except (OSError, urllib.error.URLError, KeyError, IndexError, TypeError, ValueError, LLMError) as error:
            finding.ai = None
            print(f"  triage {index}/{len(findings)} failed, keeping finding without ai: {error}", file=sys.stderr)
            continue
        verdict = finding.ai["verdict"] if finding.ai else "unparseable answer"
        print(f"  triage {index}/{len(findings)} {finding.file}:{finding.line} -> {verdict}", file=sys.stderr)
