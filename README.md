# 🛡️ VulnPath-AI

[![Python](https://img.shields.io/badge/Python-3.6+-green)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-Verified-blue)](test_results.json)

> Offline-first, stdlib-only Python hybrid scanner for AI/agent app code. Detects vulnerabilities, adds path context, and suggests fixes — with no attack or exploit features.

---

## 📖 Table of Contents

- [What is VulnPath-AI?](#what-is-vulnpath-ai)
- [Scope: what it is and what it is not](#scope-what-it-is-and-what-it-is-not)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [Supported Focus: Python AI/agent App Risks](#supported-focus-python-aiagent-app-risks)
- [Reports: Markdown, JSON, SARIF](#reports-markdown-json-sarif)
- [Safety: Fix Suggestions Only](#safety-fix-suggestions-only)
- [Testing & Validation](#testing--validation)
- [Contributing](#contributing)
- [License](#license)

---

## 🤔 What is VulnPath-AI?

**VulnPath-AI** is a lightweight, dependency-free security scanner written in pure Python (standard library only). It scans source files for common weaknesses, adds source-to-sink path context where it can, and reports each finding with a severity, confidence score, and a concrete fix suggestion.

It is designed for **AI/agent application code** — Python apps that call LLMs, build prompts, execute tools, or handle secrets — but the same patterns apply to general Python code.

---

## ⚖️ Scope: what it is and what it is not

**It is:**
- A pattern-based (regex + AST) scanner for Python, with basic support for JS/TS/Java/PHP/Ruby/Go file extensions.
- A local, offline-first tool — no API keys, no external service calls, no training data.
- A fix-suggestion generator: every finding carries a `suggestion` field with safe remediation guidance.
- A lightweight triage tool that surfaces likely issues so a human can review them.

**It is not:**
- A full enterprise SAST platform. It will miss complex, context-dependent vulnerabilities and can produce false positives and false negatives.
- An attack or exploitation tool. It does not generate payloads, exploit chains, or instructions for attacking systems.
- A substitute for a security review or penetration test.

Treat every finding as a lead to verify, not a confirmed vulnerability.

---

## 🚀 Quick Start

### Install

```bash
# From source (editable install)
git clone <repo>
cd vulnpath-ai
pip install -e .

# Or run directly without installing
python analyze_hybrid.py <target>
```

### Scan a single file

```bash
python analyze_hybrid.py samples/sqli_example.py
```

### Scan a directory (recursive)

```bash
python analyze_hybrid.py . --dir
```

---

## 💡 Usage Examples

**Scan one file, Markdown report (default):**

```bash
python analyze_hybrid.py samples/sqli_example.py
```

**Scan a directory:**

```bash
python analyze_hybrid.py . --dir
```

**JSON output (machine-readable):**

```bash
python analyze_hybrid.py samples/sqli_example.py --format json --output report.json
```

**SARIF output (CI/CD / tool integration):**

```bash
python analyze_hybrid.py samples/sqli_example.py --format sarif --output report.sarif
```

**Optional `--ai` mode (pasteable prompt for any LLM):**

`--ai` prints a ready-to-use prompt that you paste into any LLM (model-agnostic). It includes the target code plus SYSTEM_PROMPT.md guidance so the LLM can produce its own security report.

```bash
python analyze_hybrid.py samples/sqli_example.py --ai
```

**Interactive `--ai` mode (step-by-step prompts):**

```bash
python analyze_hybrid.py samples/sqli_example.py --ai --interactive
```

---

## 🎯 Supported Focus: Python AI/agent App Risks

The scanner targets the weaknesses most relevant to AI/agent application code, plus common Python issues:

| Risk | What it catches | Example fix |
|------|----------------|-------------|
| Hardcoded credentials | Passwords, API keys, secrets written in code | Load from env vars or a secrets manager |
| Command injection | User input reaching `os.system`, `subprocess.run(shell=True)`, `exec`/`eval` | Use argument lists; avoid `shell=True` |
| Unsafe eval/exec | `eval()`/`exec()` with non-literal input | Use `ast.literal_eval` only for trusted data |
| Unsafe deserialization | `pickle.loads`/`pickle.load` on untrusted data | Use JSON or another safe format |
| Path traversal | File paths built from untrusted input | Resolve and confine to a base directory |
| SQL injection | User input concatenated into SQL queries | Parameterized queries |
| Weak cryptography | MD5, SHA-1, DES, RC4 | SHA-256+, bcrypt/Argon2 for passwords |

This is a focused set of rules, not exhaustive coverage. See the "what it is not" section above.

---

## 📊 Reports: Markdown, JSON, SARIF

VulnPath-AI emits three report formats:

- **Markdown** (default) — human-readable summary with findings, fix suggestions, and path context.
- **JSON** (`--format json`) — machine-readable findings with fields `cwe_id`, `severity`, `confidence`, `line`, `suggestion`, `impact`.
- **SARIF** (`--format sarif`) — standard format for CI/CD and security tool ingestion.

Use `--output <file>` to write to a file; otherwise the report prints to stdout.

---

## ⚠️ Safety: Fix Suggestions Only

VulnPath-AI **does not** generate attack payloads, exploit chains, or instructions for compromising systems. Every finding includes a `suggestion` field with safe remediation guidance only. Do not use this tool to attack systems you do not own or have written permission to test.

---

## 🧪 Testing & Validation

Run the benchmark suite against `samples/vulnerable/` and `samples/safe/`:

```bash
python test_benchmark.py
```

Results are saved to `test_results.json`.

---

## 🤝 Contributing

We welcome small, focused contributions:

- Add new detection patterns to `analyze_hybrid.py` (keep the `cwe_id`, `severity`, `confidence`, `line`, `suggestion`, `impact` finding fields).
- Improve samples under `samples/vulnerable/` and `samples/safe/`.
- Fix documentation typos or gaps.

Please keep the stdlib-only constraint and avoid adding heavy dependencies.

---

## 📝 License

This project is licensed under the MIT License — see the LICENSE file for details.

---

**Actively maintained.** MIT License.
