"""The two finding shapes: what one tool reports, and what os-sast publishes after merging."""

from dataclasses import dataclass, field

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity)


@dataclass(frozen=True)
class RawFinding:
    """One result from one scanner, already mapped to common field names."""

    tool: str
    rule_id: str
    cwe: str | None
    severity: str
    file: str
    line: int
    message: str


@dataclass
class Finding:
    """One merged finding. Matches the `findings[]` item of the ScanResult contract."""

    fingerprint: str
    cwe: str | None
    rule_id: str
    found_by: list[str]
    severity: str
    file: str
    line: int
    message: str
    ai: dict | None = field(default=None)

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "cwe": self.cwe,
            "ruleId": self.rule_id,
            "foundBy": self.found_by,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "ai": self.ai,
        }
