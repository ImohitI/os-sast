# os-sast

An "AI SAST tool" built from open-source parts: it runs [Opengrep](https://github.com/opengrep/opengrep) with its own taint rules and [Bandit](https://github.com/PyCQA/bandit), merges their output into one ScanResult JSON, and can ask a local LLM ([Ollama](https://ollama.com)) to triage each finding.

> Part of a SAST pipeline built from open-source parts: [samples](https://github.com/ImohitI/samples) (vulnerable code + ground truth) → **os-sast** (scanner CLI) → [sast-platform](https://github.com/ImohitI/sast-platform) (ingest API, Kafka, consumer, Jenkins) → [sast-dashboard](https://github.com/ImohitI/sast-dashboard) (dashboard API + UI).  
> Design decisions: [DESIGN.md](https://github.com/ImohitI/sast-platform/blob/main/docs/DESIGN.md) · one scan followed end to end: [WALKTHROUGH.md](https://github.com/ImohitI/sast-platform/blob/main/docs/WALKTHROUGH.md)

```
os-sast scan <path> --repo samples --build 1052 --commit a1b2c3d [--ai-triage] --out result.json
os-sast eval result.json expected.json
```

## Pipeline inside `scan`

| Step | Module | What happens |
|------|--------|-------------|
| 1. Run scanners | `scanners.py` | `opengrep scan --config <rules> --json` with the bundled rules, and `bandit -r . -f json` |
| 2. Normalize | `scanners.py` | One `RawFinding` shape: rule, CWE (`CWE-89`), severity (`ERROR→HIGH`, `WARNING→MEDIUM`, `INFO→LOW`), path relative to the root |
| 3. De-duplicate | `merge.py` | Same CWE + file + line → one finding; `foundBy` lists every tool; highest severity wins. `fingerprint = sha256(cwe\|file\|line)` |
| 4. AI triage (optional) | `triage.py` | Rule, message and ±15 lines of code → Ollama `/api/generate` with a JSON schema as `format`. Adds `ai: {verdict, confidence, reason, suggestedFix}` |
| 5. Write | `cli.py` | The ScanResult contract from `sast-platform/contracts` |

**The AI only annotates, it never deletes.** A wrong "likely_fp" must not hide a real bug. If Ollama is down or answers nonsense, the finding keeps `ai: null` and the scan still succeeds.

## `eval`

Compares a result with `samples/expected.json`. A finding matches when file and CWE are equal and the line is within `--tolerance` (default 2): tools report different lines for one bug.

- **precision** = findings that point at a planted bug / all findings
- **recall** = planted bugs found / all planted bugs
- **bait hit** = findings on code that looks risky but is safe
- **hide likely_fp** row: the same numbers if you hid what the AI called false positives, plus every real bug the AI got wrong

Baseline on `samples`, no AI:

| Scanners | findings | TP | precision | recall | bait hit |
|----------|---------:|---:|----------:|-------:|---------:|
| Semgrep 1.182 `p/default` + Bandit 1.9 (before) | 21 | 12 | 0.57 | 0.71 | 1 |
| Opengrep 1.32 + bundled rules | 16 | 14 | 0.88 | 1.00 | 0 |
| Opengrep 1.32 + bundled rules + Bandit 1.9 | 19 | 15 | 0.79 | 1.00 | 1 |

**Read the 1.00 recall with care.** The bundled rules were written after looking at `samples`, so this
set measures the rules on code they were tuned near. Each rule is written per framework (sources, sinks,
sanitizers), never per sample line, but the honest number comes from a **holdout**: bugs and bait added
to `samples` after the rules were frozen. The 2 non-bait false positives are second-order flows (a value
read back from an injectable query's result and written to the response); they are left in on purpose
as triage material for the AI step.

## Rules

`src/os_sast/rules/`, one file per CWE, shipped inside the package:

| File | CWE | Languages | Kind |
|------|-----|-----------|------|
| `sql-injection.yaml` | CWE-89 | Python, PHP, JS: taint · Java, Kotlin: non-constant SQL into `java.sql.Statement` | taint / pattern |
| `command-injection.yaml` | CWE-78 | Python, Java, PHP, JS | taint |
| `path-traversal.yaml` | CWE-22 | Python, Java, PHP, JS (`basename` is a sanitizer) | taint |
| `xss.yaml` | CWE-79 | PHP, JS, Java | taint |
| `weak-hash.yaml` | CWE-328 | Java, Kotlin, Python, JS, PHP | pattern |

Every rule carries `metadata.cwe`, which is how findings get their CWE. `--rules path/to/rules` runs
your own rules (a file or a directory) instead. Opengrep runs from the rules directory, because it
prefixes every rule id with the config path relative to its working directory; run from anywhere else,
a local absolute path would end up in every finding.

`opengrep validate src/os_sast/rules` checks the rule files.

## Install and run

Opengrep is a standalone binary, not a pip package. Download it from the
[releases page](https://github.com/opengrep/opengrep/releases) and put it on your `PATH`:

```bash
curl -fsSL -o ~/.local/bin/opengrep \
  https://github.com/opengrep/opengrep/releases/download/v1.32.0/opengrep_manylinux_x86   # or _aarch64, _osx_arm64
chmod +x ~/.local/bin/opengrep && opengrep --version

python -m venv .venv && . .venv/bin/activate
pip install -e ".[scanners,dev]"     # bandit + pytest
pytest                               # the live opengrep test is skipped if the binary is missing

# AI triage: install Ollama, then
ollama pull qwen2.5-coder:7b
os-sast scan ../samples --repo samples --build 1 --ai-triage --out result.json
```

Scans run offline: the rules are local, opengrep has no metrics option, and os-sast passes `--disable-version-check`. `OLLAMA_URL` and `OLLAMA_MODEL` override the defaults (`http://localhost:11434`, `qwen2.5-coder:7b`).

Docker (the image downloads the pinned opengrep binary and checks its SHA-256):

```bash
docker build -t os-sast .
docker run --rm -v "$PWD/../samples:/src" os-sast scan . --repo samples --build 1 --out result.json
```

## Contract

`tests/contract/scan-result.schema.json` is a copy of the schema in `sast-platform/contracts`. `test_contract.py` validates real `scan` output against it, and fails if the copy drifts from `sast-platform` when both repos are checked out side by side.

## License

[Apache-2.0](LICENSE)
