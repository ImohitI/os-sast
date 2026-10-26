"""De-duplicate findings across tools: same CWE + file + line becomes one finding."""

import hashlib
from collections import defaultdict

from .model import Finding, RawFinding, severity_rank


def fingerprint(cwe: str | None, file: str, line: int) -> str:
    # Deliberately simple: adding one line above a bug changes its fingerprint, so the dashboard
    # diff shows it as "fixed" + "new". Making this survive line moves is a stretch task.
    return hashlib.sha256(f"{cwe or ''}|{file}|{line}".encode()).hexdigest()


def merge(raw_findings: list[RawFinding]) -> list[Finding]:
    groups: dict[tuple, list[RawFinding]] = defaultdict(list)
    for raw in raw_findings:
        groups[(raw.cwe, raw.file, raw.line)].append(raw)

    merged = []
    for (cwe, file, line), group in groups.items():
        # The most severe report speaks for the group; every tool that agreed is kept in foundBy.
        lead = max(group, key=lambda r: (severity_rank(r.severity), r.tool == "opengrep"))
        merged.append(Finding(
            fingerprint=fingerprint(cwe, file, line),
            cwe=cwe,
            rule_id=lead.rule_id,
            found_by=sorted({r.tool for r in group}),
            severity=lead.severity,
            file=file,
            line=line,
            message=lead.message,
        ))
    return sorted(merged, key=lambda f: (f.file, f.line, f.cwe or ""))
