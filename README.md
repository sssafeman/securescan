# 🔒 SecureScan

**AI-powered security audit pipeline for open-source repositories.**

SecureScan combines static analysis with LLM-powered semantic reasoning to find real vulnerabilities in codebases — not just pattern matches. It analyzes code context, traces data flows, debates its own findings through adversarial self-review, and generates remediation patches with explanations.

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

---

## How It Works

SecureScan runs a 7-stage pipeline on any GitHub repository:

```
GitHub Repo URL or Local Path
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│  Stage 1: INGEST     Clone repo, map file structure     │
│  Stage 2: PARSE      AST analysis, dependency scan      │
│  Stage 3: DETECT     Semgrep rules + secrets scanner    │
│  Stage 4: ANALYZE    LLM semantic vulnerability analysis│
│  Stage 5: VALIDATE   Adversarial false-positive review  │
│  Stage 6: REMEDIATE  Auto-generate code patches         │
│  Stage 7: REPORT     HTML + JSON + SARIF reports        │
└─────────────────────────────────────────────────────────┘
     │
     ▼
Security Report + Patches
```

**What makes it different from traditional SAST tools:**

- **Semantic understanding** — Claude reads the full codebase context, not just regex matches. It understands that `eval(req.body.preTax)` on line 32 is dangerous because the validation on line 47 happens *after* execution, not before.
- **Adversarial self-debate** — Every finding is challenged by a "defense attorney" persona that constructs the strongest false-positive argument. Only findings that survive cross-examination are confirmed.
- **Contextual rejection** — Bcrypt hashes in commented-out code? Rejected. Self-signed certs in development artifacts? Flagged as likely FP. The LLM understands developer intent, not just syntax.
- **Actionable patches** — For every confirmed vulnerability, SecureScan generates a validated code fix with a unified diff and plain-English explanation.

---

## Example Output

Scanning [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) (a deliberately vulnerable Node.js app):

```
SCAN RESULTS: OWASP/NodeGoat
  Files analyzed: 40
  Lines of code: 3,047
  Raw findings: 8
  After LLM analysis: 5 confirmed, 3 rejected
  After adversarial review: 4 confirmed, 1 likely FP
  Patches generated: 4/4

Validated Findings:
  ✓ CRITICAL - sqli in app/routes/contributions.js:32 (confidence: 0.99)
  ✓ CRITICAL - sqli in app/routes/contributions.js:33 (confidence: 0.99)
  ✓ CRITICAL - sqli in app/routes/contributions.js:34 (confidence: 0.99)
  ✓ MEDIUM  - xss in server.js:78 (confidence: 0.75)
  ✗ LIKELY FP - hardcoded_secret in artifacts/cert/server.key:1

3 bcrypt hashes in commented-out code: rejected (not real vulnerabilities)
```

The HTML report includes full analysis, taint chains, adversarial debate transcripts, CVSS scores, and remediation diffs.

---

## Quick Start

### Prerequisites

- Python 3.11+
- Git
- [Anthropic API key](https://console.anthropic.com/) (for LLM analysis)

### Installation

```bash
git clone https://github.com/sssafeman/securescan.git
cd securescan
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e .
pip install -r requirements.txt
```

### Configuration

```bash
cp .env.example .env
# Edit .env with your API key
```

```env
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here

# Optional: override model (default: claude-opus-4-6)
# OPUS_MODEL=claude-sonnet-4-5-20250929
```

### Run a Scan

```bash
# Full pipeline — clone and analyze a GitHub repo
securescan analyze https://github.com/OWASP/NodeGoat

# Scan a local directory (no clone)
securescan analyze-local ./my-project

# Detection only (no API key needed)
securescan analyze https://github.com/OWASP/NodeGoat --skip-llm

# PR-level diff scan — only analyze changed files
securescan analyze-local . --diff origin/main
```

Reports are saved to `reports/` as HTML, JSON, and SARIF.

---

## Language Support

| Language | Parser | Semgrep Rules | Detection |
|----------|--------|---------------|-----------|
| **Python** | tree-sitter + regex | `p/python` | `eval()`, `exec()`, secrets, SQL injection |
| **JavaScript/TypeScript** | tree-sitter + regex | `p/javascript` | XSS, injection, insecure cookies |
| **Go** | Regex | `p/golang` | `exec.Command`, raw SQL, `unsafe.Pointer` |
| **Java** | Regex | `p/java`, `p/spring` | `Runtime.exec`, deserialization, SSRF, XXE |
| **Rust** | Regex | LLM analysis | `unsafe` blocks, `Command::new`, raw pointers |

---

## Vulnerability Coverage

| Category | Detection Method | Examples |
|----------|-----------------|----------|
| **Code Injection** | Semgrep + LLM | `eval()`, `exec()`, `exec.Command`, `Runtime.exec` |
| **SQL Injection** | Semgrep + LLM | String interpolation in queries, raw `sql.Query` |
| **XSS** | Semgrep + LLM | Missing httpOnly, innerHTML, reflected input, template injection |
| **Hardcoded Secrets** | Regex + entropy + LLM | API keys, private keys, tokens, passwords |
| **Command Injection** | Semgrep + LLM | Shell execution with user input |
| **Deserialization** | Semgrep + LLM | `ObjectInputStream`, unsafe unmarshalling |
| **Path Traversal** | Semgrep + LLM | Unsanitized file path construction |

The LLM layer adds semantic understanding on top of static detection — it traces taint chains, checks if sanitization exists, and evaluates whether findings are reachable from user input.

---

## Custom Configuration

Create a `.securescan.yml` in your repo root or pass `--config <path>`:

```yaml
# Enable/disable specific checks
checks:
  sqli: true
  xss: true
  hardcoded_secret: true
  command_injection: true
  deserialization: true
  path_traversal: true

# Exclude files and directories
exclude:
  paths:
    - "node_modules/"
    - "vendor/"
    - "dist/"
  patterns:
    - "*.min.js"
    - "*.test.js"

# Minimum severity to report (low, medium, high, critical)
min_severity: low

# Minimum confidence for adversarial review
confidence_threshold: 0.7

# LLM concurrency settings
llm:
  max_concurrent: 5
  max_retries: 3
```

---

## GitHub Actions

SecureScan ships as a reusable GitHub Action. Add it to any repo:

```yaml
# .github/workflows/securescan.yml
name: SecureScan Security Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  security-events: write
  contents: read

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Needed for diff scanning

      - uses: sssafeman/securescan@main
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          # On PRs, only scan changed files
          diff-base: ${{ github.event_name == 'pull_request' && github.event.pull_request.base.sha || '' }}
```

SARIF results are automatically uploaded to the GitHub Security tab. Reports are available as workflow artifacts.

See `.github/workflows/securescan.yml.example` for the full example.

---

## Architecture

```
securescan/
├── ingest/          # Git clone, file discovery
│   ├── repo.py      # Repository cloning and management
│   └── manifest.py  # File manifest with risk scoring
├── parse/           # AST analysis
│   ├── treesitter.py # tree-sitter + regex fallback parser
│   ├── parser.py    # Regex parser helpers (Go, Rust, Java)
│   └── dependencies.py  # Dependency extraction
├── detect/          # Static analysis
│   ├── semgrep_runner.py  # Semgrep integration
│   ├── secrets_scanner.py # Entropy + regex secrets detection
│   └── models.py    # Data models (RawFinding, EnrichedFinding, etc.)
├── analyze/         # LLM-powered analysis
│   ├── opus_client.py           # Anthropic API client
│   ├── codebase_digest.py       # Context builder for LLM
│   ├── vulnerability_analyzer.py # Semantic analysis prompts
│   └── adversarial_reviewer.py  # False-positive debate
├── remediate/       # Patch generation
│   └── patch_generator.py  # LLM-powered code fix generation
├── report/          # Report generation
│   ├── generator.py      # HTML + JSON + SARIF report builder
│   └── templates/
│       └── report.html   # Dark-theme HTML template
├── diff.py          # Git diff utilities for PR scanning
├── rule_config.py   # YAML rule configuration loader
├── pipeline.py      # 7-stage orchestrator
├── cli.py           # Click CLI interface
└── config.py        # Configuration management
```

---

## How the LLM Analysis Works

### Stage 4: Vulnerability Analyzer

Each raw finding from semgrep/secrets scanning is sent to Claude with the full codebase context (~24K tokens for a typical small repo). The LLM acts as a senior security engineer and returns:

- Whether the finding is a genuine vulnerability (with reasoning)
- Severity classification (critical/high/medium/low)
- CVSS score estimate
- Taint chain (source → sink data flow)
- Exploitability assessment
- Whether the vulnerability is reachable from user input

Findings the LLM determines are not real vulnerabilities are **rejected** with an explanation.

### Stage 5: Adversarial Reviewer

Confirmed findings are then challenged by an adversarial "defense attorney" persona that:

1. Constructs the **strongest possible false-positive argument** for each finding
2. Evaluates the strength of its own argument
3. Provides a **rebuttal** explaining why the finding is (or isn't) a real vulnerability

Only findings that survive this cross-examination with sufficient confidence are marked as confirmed.

### Stage 6: Patch Generator

For confirmed vulnerabilities, the LLM generates:

- Complete fixed code with minimal changes
- Unified diff for review
- Plain-English explanation of what was changed and why
- Syntax validation of the generated fix

All LLM stages run in parallel (configurable up to 10 concurrent calls) for fast scans.

---

## Cost

Typical scan costs with Claude Opus 4.6:

| Repository Size | Findings | API Calls | Tokens | Est. Cost |
|----------------|----------|-----------|--------|-----------|
| Small (3K LOC) | 8 raw → 4 confirmed | 18 | ~49K | ~$1.50 |

Using Claude Sonnet is ~5x cheaper (~$0.30/scan) with comparable analysis quality for most cases. Diff scanning on PRs reduces costs further by only analyzing changed files.

---

## Testing

```bash
# Run all tests (67 tests)
pytest tests/ -v

# Detection only (no API key needed)
securescan analyze https://github.com/pallets/flask --skip-llm
```

---

## Tech Stack

- **Claude Opus 4.6** — Codebase analysis, vulnerability reasoning, adversarial review, patch generation
- **Semgrep** — Static analysis rule engine
- **tree-sitter** — AST parsing (with regex fallback for Go, Rust, Java)
- **Rich** — Terminal output formatting
- **Jinja2** — HTML report templating
- **Click** — CLI framework
- **PyYAML** — Rule configuration

---

## License

MIT — see [LICENSE](LICENSE)

---

*Built by [@sssafeman](https://github.com/sssafeman)*
