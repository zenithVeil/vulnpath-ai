# VulnPath AI
Hybrid code-security scanner, stdlib-only Python.
Files: analyze_hybrid.py (main CLI, regex + merge logic), ast_analyzer.py (Python AST detection),
SYSTEM_PROMPT.md (LLM prompt for --ai mode), test_benchmark.py, samples/.

Rules:
- Do NOT rewrite or remove existing detection logic, report formats (JSON/Markdown/SARIF),
  CLI flags, or working samples.
- Stdlib only. Do not add packages.
- Never hardcode API keys. Use environment variables only. Keep .env in .gitignore.
- Findings keep these fields: cwe_id, severity, confidence, line, suggestion, impact.
  No invented CVSS scores or dollar estimates.
- Do not create new top-level packages or folders (no vulnpath/ or prompts/). Edit existing files.
- Ask before deleting or overwriting any existing file. Make small changes and explain each one.
