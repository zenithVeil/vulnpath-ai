"""VulnPath AI — Core Vulnerability Scanner.

Handles source code ingestion, line-number formatting, LLM communication,
and strict schema validation for security findings.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

# Allowed severity levels
VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}

# Allowed confidence levels
VALID_CONFIDENCES = {"High", "Medium", "Low"}

# Required keys for each finding
REQUIRED_FINDING_KEYS = {
    "name",
    "cwe",
    "severity",
    "confidence",
    "line",
    "evidence",
    "description",
    "attack_scenario",
    "fix",
    "why_it_matters",
}


@dataclass
class Finding:
    """Represents a single validated vulnerability finding."""

    name: str
    cwe: str
    severity: str
    confidence: str
    line: int
    evidence: str
    description: str
    attack_scenario: str
    fix: str
    why_it_matters: str

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to standard dictionary."""
        return asdict(self)


@dataclass
class ScanResult:
    """Represents the complete result of scanning a file or code snippet."""

    file_path: str
    security_score: int
    findings: list[Finding]
    raw_response: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert scan result to a dictionary."""
        return {
            "file_path": self.file_path,
            "security_score": self.security_score,
            "findings": [f.to_dict() for f in self.findings],
            "total_findings": len(self.findings),
        }


def add_line_numbers(source_code: str) -> str:
    """Prefix each line of source code with its 1-based line number.

    Example output:
       1 | def example():
       2 |     return True
    """
    lines = source_code.splitlines()
    if not lines:
        return "   1 | "
    max_num_width = max(len(str(len(lines))), 4)
    numbered_lines = [
        f"{idx + 1:>{max_num_width}} | {line}"
        for idx, line in enumerate(lines)
    ]
    return "\n".join(numbered_lines)


def call_llm(system_prompt: str, user_prompt: str) -> str:
    """Placeholder LLM invocation function.

    NOTE: This is a placeholder as per project requirements.
    No live external API calls are made here. For local testing and development,
    this function inspects the input for common vulnerability signatures
    and returns a compliant JSON response.
    """
    # Parse line-numbered lines from the user prompt for realistic mock findings
    findings: list[dict[str, Any]] = []
    lines = user_prompt.splitlines()

    for raw_line in lines:
        match = re.match(r"^\s*(\d+)\s*\|\s*(.*)$", raw_line)
        if not match:
            continue
        line_num = int(match.group(1))
        content = match.group(2).strip()

        # Check for SQL Injection (CWE-89)
        if re.search(r"SELECT.*FROM.*\+|SELECT.*FROM.*%s|cursor\.execute\(f[\"'].*SELECT", content, re.IGNORECASE):
            findings.append({
                "name": "SQL Injection via String Formatting",
                "cwe": "CWE-89",
                "severity": "Critical",
                "confidence": "High",
                "line": line_num,
                "evidence": content,
                "description": "User input is directly concatenated or formatted into dynamic SQL queries without parameterized queries.",
                "attack_scenario": "An attacker can provide SQL control characters (e.g., ' OR '1'='1) to alter logic and exfiltrate database contents.",
                "fix": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE username = %s', (username,))",
                "why_it_matters": "Enables attackers to bypass authentication, dump sensitive database tables, or modify database records.",
            })

        # Check for Hardcoded Credentials (CWE-798)
        elif re.search(r"(SECRET_KEY|API_KEY|PASSWORD|TOKEN)\s*=\s*[\"'][^\"']+[\"']", content, re.IGNORECASE):
            findings.append({
                "name": "Hardcoded Sensitive Credential",
                "cwe": "CWE-798",
                "severity": "High",
                "confidence": "High",
                "line": line_num,
                "evidence": content,
                "description": "A secret token, credential, or API key is stored directly in source code instead of an environment variable.",
                "attack_scenario": "Anyone with read access to the repository or decompiled binary can extract the secret and access protected resources.",
                "fix": "Store secrets in environment variables or a secrets manager: os.environ.get('API_KEY')",
                "why_it_matters": "Leaked credentials can grant persistent, unauthorized administrative access to external services.",
            })

        # Check for Path Traversal (CWE-22)
        elif re.search(r"open\(f?[\"'][^\"']*/.*\{|open\(os\.path\.join\(.*filename", content):
            findings.append({
                "name": "Path Traversal via Unsanitized File Access",
                "cwe": "CWE-22",
                "severity": "High",
                "confidence": "Medium",
                "line": line_num,
                "evidence": content,
                "description": "File paths are constructed from user input without validation or normalization.",
                "attack_scenario": "An attacker can supply dot-dot-slash sequence ('../../etc/passwd') to access files outside the intended directory.",
                "fix": "Sanitize user paths with os.path.basename and verify the resolved path is within the allowed directory.",
                "why_it_matters": "Allows unauthorized arbitrary file reading or writing on the host filesystem.",
            })

        # Check for Command Injection (CWE-78)
        elif re.search(r"os\.system\(|subprocess\.call\(.*shell=True|subprocess\.Popen\(.*shell=True", content):
            findings.append({
                "name": "OS Command Injection",
                "cwe": "CWE-78",
                "severity": "Critical",
                "confidence": "High",
                "line": line_num,
                "evidence": content,
                "description": "System command execution occurs using shell expansion or unescaped user parameters.",
                "attack_scenario": "An attacker can append command separators (e.g., '; id; reboot') to execute arbitrary operating system commands.",
                "fix": "Avoid shell=True and pass command arguments as a list of strings: subprocess.run(['cmd', arg], check=True)",
                "why_it_matters": "Command injection leads directly to remote code execution and server compromise.",
            })

    # Calculate mock security score based on findings count
    if not findings:
        score = 100
    else:
        penalty = sum(30 if f["severity"] == "Critical" else 20 if f["severity"] == "High" else 10 for f in findings)
        score = max(0, 100 - penalty)

    response_payload = {
        "security_score": score,
        "findings": findings,
    }
    return json.dumps(response_payload, indent=2)


def validate_findings(raw_response: str | dict[str, Any]) -> tuple[int, list[Finding]]:
    """Validate JSON findings returned from the LLM.

    Ensures:
    - Valid JSON payload.
    - security_score is an integer between 0 and 100.
    - findings is a list of well-structured objects.
    - Every finding contains all mandatory fields:
      name, cwe, severity, confidence, line, evidence, description,
      attack_scenario, fix, why_it_matters.
    - Strict prohibition of invented CVSS scores or dollar estimates.
    """
    if isinstance(raw_response, str):
        cleaned = raw_response.strip()
        # Strip potential markdown fences if present
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as err:
            raise ValueError(f"LLM output is not valid JSON: {err}") from err
    elif isinstance(raw_response, dict):
        data = raw_response
    else:
        raise TypeError("raw_response must be a JSON string or dict")

    if not isinstance(data, dict):
        raise ValueError("Root JSON structure must be an object/dict")

    # Validate security_score
    if "security_score" not in data:
        raise ValueError("Missing 'security_score' in LLM response")
    score = data["security_score"]
    if not isinstance(score, (int, float)) or not (0 <= score <= 100):
        raise ValueError(f"'security_score' must be a number between 0 and 100 (got {score})")
    security_score = int(score)

    # Validate findings array
    if "findings" not in data:
        raise ValueError("Missing 'findings' list in LLM response")
    raw_findings = data["findings"]
    if not isinstance(raw_findings, list):
        raise ValueError("'findings' must be a list")

    validated_findings: list[Finding] = []
    for idx, item in enumerate(raw_findings):
        if not isinstance(item, dict):
            raise ValueError(f"Finding item at index {idx} is not an object")

        # Disallow invented metrics per project policy
        disallowed_keys = {"cvss", "cvss_score", "dollar_estimate", "dollar_cost", "financial_loss"}
        present_disallowed = disallowed_keys.intersection(item.keys())
        if present_disallowed:
            raise ValueError(
                f"Finding at index {idx} contains disallowed speculative metrics: {present_disallowed}"
            )

        # Check required keys
        missing_keys = REQUIRED_FINDING_KEYS - set(item.keys())
        if missing_keys:
            raise ValueError(
                f"Finding at index {idx} is missing required fields: {sorted(missing_keys)}"
            )

        # Validate CWE format (e.g., 'CWE-89')
        cwe = str(item["cwe"]).strip()
        if not re.match(r"^CWE-\d+$", cwe, re.IGNORECASE):
            raise ValueError(
                f"Finding at index {idx} has invalid CWE format: '{cwe}' (expected e.g. 'CWE-89')"
            )

        # Validate line number
        line_val = item["line"]
        if not isinstance(line_val, int) or line_val < 1:
            raise ValueError(
                f"Finding at index {idx} has invalid line number: {line_val} (must be integer >= 1)"
            )

        # Validate severity
        severity = str(item["severity"]).capitalize()
        if severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Finding at index {idx} has invalid severity '{severity}' (allowed: {VALID_SEVERITIES})"
            )

        # Validate confidence
        confidence = str(item["confidence"]).capitalize()
        if confidence not in VALID_CONFIDENCES:
            raise ValueError(
                f"Finding at index {idx} has invalid confidence '{confidence}' (allowed: {VALID_CONFIDENCES})"
            )

        # Validate evidence
        evidence = str(item["evidence"]).strip()
        if not evidence:
            raise ValueError(f"Finding at index {idx} has empty 'evidence'")

        validated_findings.append(
            Finding(
                name=str(item["name"]).strip(),
                cwe=cwe.upper(),
                severity=severity,
                confidence=confidence,
                line=line_val,
                evidence=evidence,
                description=str(item["description"]).strip(),
                attack_scenario=str(item["attack_scenario"]).strip(),
                fix=str(item["fix"]).strip(),
                why_it_matters=str(item["why_it_matters"]).strip(),
            )
        )

    return security_score, validated_findings


def scan_code(
    source_code: str,
    file_path: str = "snippet.py",
    system_prompt: str | None = None,
) -> ScanResult:
    """Scan source code string for vulnerabilities.

    1. Adds line numbers to the code.
    2. Sends code to LLM with the system prompt.
    3. Validates JSON findings.
    4. Returns ScanResult.
    """
    numbered_code = add_line_numbers(source_code)

    if system_prompt is None:
        prompt_file = Path(__file__).resolve().parent.parent / "prompts" / "system_prompt.md"
        if prompt_file.exists():
            system_prompt = prompt_file.read_text(encoding="utf-8")
        else:
            system_prompt = "You are a code-security scanner. Return valid JSON only."

    user_prompt = f"Target File: {file_path}\n\nSource Code:\n{numbered_code}"
    raw_response = call_llm(system_prompt=system_prompt, user_prompt=user_prompt)

    score, findings = validate_findings(raw_response)
    raw_dict = json.loads(raw_response) if isinstance(raw_response, str) else raw_response

    return ScanResult(
        file_path=file_path,
        security_score=score,
        findings=findings,
        raw_response=raw_dict,
    )


def scan_file(file_path: str | Path, system_prompt_path: str | Path | None = None) -> ScanResult:
    """Read a source file from disk and scan it for vulnerabilities."""
    path_obj = Path(file_path)
    if not path_obj.exists() or not path_obj.is_file():
        raise FileNotFoundError(f"Target file not found: {file_path}")

    source_code = path_obj.read_text(encoding="utf-8", errors="replace")

    system_prompt = None
    if system_prompt_path is not None:
        sp_path = Path(system_prompt_path)
        if sp_path.exists():
            system_prompt = sp_path.read_text(encoding="utf-8")

    return scan_code(source_code=source_code, file_path=str(path_obj), system_prompt=system_prompt)
