# VulnPath AI — Project Guidelines

- **Project Purpose**: VulnPath AI is a defensive code-security scanner written in Python 3.11+.
- **Core Workflow**: Read source code -> add line numbers -> send to an LLM -> validate JSON findings -> render a report.
- **Environment & Secrets**: Never hardcode API keys. Use a `.env` file and keep it in `.gitignore`.
- **Finding Standards**: Every finding must include a CWE ID, exact evidence (quoted code), and a confidence level. Do not invent CVSS scores or dollar estimates.
- **Code Style & Maintenance**: Keep code simple and commented. Do not delete existing files without asking.
