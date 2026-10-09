"""VulnPath AI — Report Generator.

Transforms validated ScanResult instances into formatted Markdown,
JSON, or console-friendly text reports.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vulnpath.scanner import ScanResult


def render_markdown_report(result: ScanResult) -> str:
    """Generate a clean, professional Markdown security report."""
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Severity counters
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for finding in result.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    lines: list[str] = [
        "# 🛡️ VulnPath AI — Security Scan Report",
        "",
        f"- **Target File**: `{result.file_path}`",
        f"- **Scan Timestamp**: {now_utc}",
        f"- **Security Score**: **{result.security_score} / 100**",
        f"- **Total Findings**: {len(result.findings)}",
        "",
        "## Summary by Severity",
        "",
        "| Severity | Count |",
        "| :--- | :--- |",
        f"| 🔴 Critical | {counts['Critical']} |",
        f"| 🟠 High | {counts['High']} |",
        f"| 🟡 Medium | {counts['Medium']} |",
        f"| 🔵 Low | {counts['Low']} |",
        f"| ⚪ Info | {counts['Info']} |",
        "",
        "---",
        "",
    ]

    if not result.findings:
        lines.extend([
            "## Findings",
            "",
            "✅ **No security vulnerabilities detected.** The inspected code adheres to the evaluated baseline.",
            "",
        ])
        return "\n".join(lines)

    lines.append("## Vulnerability Findings\n")

    for idx, f in enumerate(result.findings, start=1):
        severity_icon = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🔵",
            "Info": "⚪",
        }.get(f.severity, "⚠️")

        lines.extend([
            f"### {idx}. {severity_icon} {f.name}",
            "",
            f"- **CWE**: `{f.cwe}`",
            f"- **Severity**: **{f.severity}**",
            f"- **Confidence**: {f.confidence}",
            f"- **Line Number**: `{f.line}`",
            "",
            "#### Quoted Evidence",
            "```text",
            f"{f.evidence}",
            "```",
            "",
            "#### Description",
            f"{f.description}",
            "",
            "#### Attack Scenario",
            f"{f.attack_scenario}",
            "",
            "#### Recommended Remediation",
            "```text",
            f"{f.fix}",
            "```",
            "",
            "#### Why It Matters",
            f"{f.why_it_matters}",
            "",
            "---",
            "",
        ])

    return "\n".join(lines)


def render_json_report(result: ScanResult, indent: int = 2) -> str:
    """Serialize the scan result to formatted JSON."""
    return json.dumps(result.to_dict(), indent=indent)


def render_console_summary(result: ScanResult) -> str:
    """Generate a compact plain-text summary suitable for terminal output."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for finding in result.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    lines = [
        "========================================",
        "  VulnPath AI — Scan Summary",
        "========================================",
        f"Target:         {result.file_path}",
        f"Security Score: {result.security_score}/100",
        f"Total Findings: {len(result.findings)}",
        "----------------------------------------",
        f"Critical: {counts['Critical']} | High: {counts['High']} | Medium: {counts['Medium']} | Low: {counts['Low']} | Info: {counts['Info']}",
        "========================================",
    ]

    for idx, f in enumerate(result.findings, start=1):
        lines.extend([
            f"[{idx}] {f.severity.upper()} - {f.name} ({f.cwe})",
            f"    Line {f.line}: {f.evidence}",
            f"    Confidence: {f.confidence}",
            f"    Fix: {f.fix}",
        ])

    return "\n".join(lines)
