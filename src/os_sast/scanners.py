"""Run each scanner as a subprocess and map its JSON output to RawFinding."""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from .model import RawFinding

_CWE = re.compile(r"CWE-(\d+)")

_OPENGREP_SEVERITY = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}

# Our own rules, shipped inside the package: one YAML file per CWE.
BUNDLED_RULES = Path(__file__).parent / "rules"

_INSTALL_HINT = {
    "opengrep": "see https://github.com/opengrep/opengrep/releases",
    "bandit": "pip install 'os-sast[scanners]'",
}


class ScannerError(RuntimeError):
    pass


def _require(binary: str) -> str:
    path = shutil.which(binary)
    if path is None:
        raise ScannerError(f"{binary} is not installed ({_INSTALL_HINT[binary]})")
    return path


def _version(binary: str) -> str | None:
    out = subprocess.run([binary, "--version"], capture_output=True, text=True, check=False).stdout
    match = re.search(r"\d+\.\d+(\.\d+)?", out)
    return match.group(0) if match else None


def _relative(root: str, path: str) -> str:
    # Every tool reports paths differently ("./python/app.py", absolute, ...). The fingerprint
    # includes the path, so it must be the same string no matter which tool found the bug.
    return os.path.relpath(os.path.join(root, path), root).replace(os.sep, "/")


def _first_cwe(value) -> str | None:
    values = value if isinstance(value, list) else [value]
    for item in values:
        match = _CWE.search(str(item))
        if match:
            return f"CWE-{match.group(1)}"
    return None


# --- opengrep --------------------------------------------------------------

def run_opengrep(root: str, rules: str | Path = BUNDLED_RULES) -> tuple[list[RawFinding], str | None]:
    binary = _require("opengrep")
    rules = Path(rules).resolve()
    rules_dir, config = (rules, ".") if rules.is_dir() else (rules.parent, rules.name)
    # Run from the rules directory: opengrep prefixes each rule id with the config path relative to
    # the working directory, which would otherwise put an absolute local path into every finding.
    proc = subprocess.run(
        [binary, "scan", "--config", config, "--json", "--quiet", "--disable-version-check", root],
        cwd=rules_dir, capture_output=True, text=True, check=False,
    )
    # 0 = no findings, 1 = findings; anything else is a real failure.
    if proc.returncode not in (0, 1):
        raise ScannerError(f"opengrep failed ({proc.returncode}): {proc.stderr.strip()[-500:]}")
    data = json.loads(proc.stdout)
    return parse_opengrep(data, root), data.get("version") or _version(binary)


def parse_opengrep(data: dict, root: str) -> list[RawFinding]:
    findings = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        findings.append(RawFinding(
            tool="opengrep",
            rule_id=result["check_id"],
            cwe=_first_cwe(extra.get("metadata", {}).get("cwe")),
            severity=_OPENGREP_SEVERITY.get(extra.get("severity", ""), "LOW"),
            file=_relative(root, result["path"]),
            line=result["start"]["line"],
            message=extra.get("message", "").strip(),
        ))
    return findings


# --- bandit ----------------------------------------------------------------

def run_bandit(root: str) -> tuple[list[RawFinding], str | None]:
    binary = _require("bandit")
    proc = subprocess.run(
        [binary, "-r", ".", "-f", "json", "-q"],
        cwd=root, capture_output=True, text=True, check=False,
    )
    # Bandit exits 1 when it finds issues, so the exit code alone can't tell success from failure.
    if not proc.stdout.strip():
        raise ScannerError(f"bandit failed ({proc.returncode}): {proc.stderr.strip()[-500:]}")
    return parse_bandit(json.loads(proc.stdout), root), _version(binary)


def parse_bandit(data: dict, root: str) -> list[RawFinding]:
    findings = []
    for result in data.get("results", []):
        cwe_id = (result.get("issue_cwe") or {}).get("id")
        findings.append(RawFinding(
            tool="bandit",
            rule_id=f"bandit.{result['test_id']}.{result['test_name']}",
            cwe=f"CWE-{cwe_id}" if cwe_id else None,
            severity=result.get("issue_severity", "LOW").upper(),
            file=_relative(root, result["filename"]),
            line=result["line_number"],
            message=result.get("issue_text", "").strip(),
        ))
    return findings
