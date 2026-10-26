"""Precision and recall of a scan result against expected.json, with and without the AI verdicts.

Matching: a finding matches an expected entry when the file and CWE are equal and the line is within
`tolerance` lines. Tools report different lines for one bug (where the tainted value is built vs. the
sink), so an exact line match would undercount.

- precision = findings that point at a planted bug / all findings
- recall    = planted bugs found by at least one finding / all planted bugs

"With AI" means: what if we hid every finding the AI called likely_fp? os-sast never does that,
but the numbers show what such a filter would gain (precision) and cost (recall).
"""

from dataclasses import dataclass


@dataclass
class Score:
    findings: int
    true_positives: int
    bugs_found: int
    bugs_total: int
    bait_flagged: int
    missed: list[dict]

    @property
    def precision(self) -> float:
        return self.true_positives / self.findings if self.findings else 0.0

    @property
    def recall(self) -> float:
        return self.bugs_found / self.bugs_total if self.bugs_total else 0.0


def _matches(finding: dict, entry: dict, tolerance: int) -> bool:
    return (
        finding["file"] == entry["file"]
        and finding.get("cwe") == entry["cwe"]
        and abs(finding["line"] - entry["line"]) <= tolerance
    )


def score(findings: list[dict], expected: list[dict], tolerance: int) -> Score:
    bugs = [e for e in expected if e["isVulnerable"]]
    bait = [e for e in expected if not e["isVulnerable"]]
    found = set()
    true_positives = bait_flagged = 0
    for finding in findings:
        hits = [i for i, bug in enumerate(bugs) if _matches(finding, bug, tolerance)]
        if hits:
            true_positives += 1
            found.update(hits)
        elif any(_matches(finding, b, tolerance) for b in bait):
            bait_flagged += 1
    return Score(
        findings=len(findings),
        true_positives=true_positives,
        bugs_found=len(found),
        bugs_total=len(bugs),
        bait_flagged=bait_flagged,
        missed=[bug for i, bug in enumerate(bugs) if i not in found],
    )


def evaluate(result: dict, expected: dict, tolerance: int = 2) -> str:
    entries = expected["entries"]
    findings = result["findings"]
    baseline = score(findings, entries, tolerance)
    lines = [
        f"{'':16}{'findings':>9}{'TP':>5}{'precision':>11}{'recall':>9}{'bait hit':>10}",
        _row("all findings", baseline),
    ]

    triaged = [f for f in findings if f.get("ai")]
    if triaged:
        kept = [f for f in findings if not (f.get("ai") and f["ai"]["verdict"] == "likely_fp")]
        lines.append(_row("hide likely_fp", score(kept, entries, tolerance)))
        bugs = [e for e in entries if e["isVulnerable"]]
        wrong = [
            f for f in findings
            if f.get("ai") and f["ai"]["verdict"] == "likely_fp"
            and any(_matches(f, bug, tolerance) for bug in bugs)
        ]
        lines.append("")
        lines.append(f"AI triaged {len(triaged)}/{len(findings)} findings; "
                     f"{len(wrong)} real bug finding(s) called likely_fp (these would be lost by a filter):")
        lines += [f"  - {f['file']}:{f['line']} {f['cwe']} ({f['ai'].get('reason')})" for f in wrong]
    else:
        lines.append("(no AI verdicts in this result: run scan with --ai-triage to compare)")

    lines.append("")
    lines.append(f"Missed planted bugs ({len(baseline.missed)}):")
    lines += [f"  - {b['file']}:{b['line']} {b['cwe']} {b.get('note', '')}" for b in baseline.missed]
    return "\n".join(lines)


def _row(label: str, s: Score) -> str:
    return (f"{label:16}{s.findings:>9}{s.true_positives:>5}{s.precision:>11.2f}"
            f"{s.recall:>9.2f}{s.bait_flagged:>10}")
