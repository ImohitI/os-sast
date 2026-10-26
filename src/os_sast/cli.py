"""os-sast scan <path> ... --out result.json   |   os-sast eval result.json expected.json"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from . import __version__
from .evaluate import evaluate
from .merge import merge
from .scanners import BUNDLED_RULES, ScannerError, run_bandit, run_opengrep
from .triage import triage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="os-sast", description=__doc__)
    parser.add_argument("--version", action="version", version=f"os-sast {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="run the scanners and write one ScanResult JSON")
    scan.add_argument("path")
    scan.add_argument("--repo", required=True, help="repoId, also the Kafka key downstream")
    scan.add_argument("--build", required=True, type=int, help="CI build number (the idempotency key)")
    scan.add_argument("--commit", help="commit SHA")
    scan.add_argument("--out", required=True)
    scan.add_argument("--rules", default=str(BUNDLED_RULES),
                      help="opengrep rules: a YAML file or a directory (default: the rules bundled with os-sast)")
    scan.add_argument("--no-bandit", action="store_true")
    scan.add_argument("--ai-triage", action="store_true", help="annotate each finding with a local LLM verdict")
    scan.add_argument("--ollama-url", default=os.environ.get("OLLAMA_URL", "http://localhost:11434"))
    scan.add_argument("--model", default=os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b"))

    ev = commands.add_parser("eval", help="precision/recall of a result against expected.json")
    ev.add_argument("result")
    ev.add_argument("expected")
    ev.add_argument("--tolerance", type=int, default=2, help="max line distance for a match")
    return parser


def scan(args) -> int:
    root = os.path.abspath(args.path)
    raw, tools = [], []

    print(f"opengrep ({args.rules}) on {root}", file=sys.stderr)
    found, version = run_opengrep(root, args.rules)
    raw += found
    tools.append({"name": "opengrep", "version": version})

    if not args.no_bandit:
        print("bandit", file=sys.stderr)
        found, version = run_bandit(root)
        raw += found
        tools.append({"name": "bandit", "version": version})

    findings = merge(raw)
    print(f"{len(raw)} raw results -> {len(findings)} findings after de-duplication", file=sys.stderr)

    if args.ai_triage:
        print(f"AI triage with {args.model} at {args.ollama_url}", file=sys.stderr)
        triage(findings, root, args.ollama_url, args.model)

    result = {
        "repoId": args.repo,
        "buildId": args.build,
        "commitSha": args.commit,
        "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": tools,
        "findings": [f.to_dict() for f in findings],
    }
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


def run_eval(args) -> int:
    with open(args.result, encoding="utf-8") as r, open(args.expected, encoding="utf-8") as e:
        print(evaluate(json.load(r), json.load(e), args.tolerance))
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return scan(args) if args.command == "scan" else run_eval(args)
    except ScannerError as error:
        print(f"os-sast: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
