# analyze_hybrid.py - Combined AI + Pattern Detection with Path Analysis
import os
import json
import sys
import re
import ast
import py_compile
import tempfile
import time
import importlib.util
from datetime import datetime
from pathlib import Path

if importlib.util.find_spec("pathspec") is not None:
    import pathspec
else:
    pathspec = None

class VulnPathAI:
    LANGUAGE_EXTENSIONS = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.java': 'java',
        '.php': 'php',
        '.rb': 'ruby',
        '.go': 'go',
        '.rs': 'rust',
        '.swift': 'swift',
        '.kt': 'kotlin',
        '.scala': 'scala',
        '.html': 'html',
        '.htm': 'html',
        '.cs': 'csharp',
        '.c': 'c',
        '.cpp': 'cpp',
        '.h': 'c',
        '.hpp': 'cpp',
    }

    def __init__(self):
        self.patterns = {
            'python': {
                'sql_injection': {
                    'cwe': 'CWE-89',
                    'severity': 'Critical',
                    'patterns': [
                        r"SELECT.*\+.*input",
                        r"execute\s*\(.*\+.*\)",
                        r"cursor\.execute\s*\(.*%.*\)",
                        r"SELECT.*%s.*%",
                        r"f['\"].*SELECT.*\{.*\}",
                        r"cursor\.execute\(.*f['\"]",
                        r"db\.execute\(.*f['\"]",
                        r"execute\(.*['\"].*\{.*\}.*['\"]\)",
                        r"f['\"].*SELECT.*\{.*\}.*['\"]",
                        r"f['\"]{3}.*?SELECT.*?\{.*?\}.*?['\"]{3}",
                        r"text\(.*f['\"]",
                        r"session\.execute\(.*f['\"]",
                        r"\.raw\(.*f['\"]",
                        r"connection\.execute\(.*f['\"]",
                        r"\.filter\(.*f['\"]",
                        r"format\(.*\{.*\}.*\)",
                        r"['\"].*\%s.*['\"]\s*\%"
                    ],
                    'description': 'SQL Injection: User input concatenated into SQL query',
                    'fix': 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))',
                    'example_attack': "SELECT * FROM users WHERE id='1' OR '1'='1'",
                    'impact': 'Full database compromise, data theft, data modification'
                },
                'command_injection': {
                    'cwe': 'CWE-78',
                    'severity': 'Critical',
                    'patterns': [
                        r"os\.system\(.*['\"].*\+",
                        r"subprocess\.(call|Popen|run)\(.*['\"].*\+",
                        r"subprocess\.(call|Popen|run)\(.*shell\s*=\s*True",
                        r"exec\(.*['\"].*\+",
                        r"eval\(.*['\"].*\+",
                        r"os\.popen\(.*['\"].*\+",
                        r"`.*\+.*`"
                    ],
                    'description': 'Command Injection: User-controlled input is concatenated into shell commands',
                    'fix': 'Use shlex.quote() for shell arguments or pass command arguments as a list to subprocess without shell=True.',
                    'example_attack': '; rm -rf /',
                    'impact': 'Remote code execution, system compromise'
                },
                'hardcoded_credentials': {
                    'cwe': 'CWE-798',
                    'severity': 'Critical',
                    'patterns': [
                        r"(?<!['\"#//])(?<!getenv)(?<!environ)(?<!env\.)(?<!process\.env)^[ \t]*password\s*[:=]\s*['\"][^'\"]+['\"]",
                        r"(?<!['\"#//])(?<!getenv)(?<!environ)(?<!env\.)(?<!process\.env)^[ \t]*api_key\s*[:=]\s*['\"][^'\"]+['\"]",
                        r"(?<!['\"#//])(?<!getenv)(?<!environ)(?<!env\.)(?<!process\.env)^[ \t]*secret\s*[:=]\s*['\"][^'\"]+['\"]",
                        r"(?<!['\"#//])(?<!getenv)(?<!environ)(?<!env\.)(?<!process\.env)^[ \t]*token\s*[:=]\s*['\"][^'\"]+['\"]"
                    ],
                    'description': 'Hardcoded credentials found in code',
                    'fix': 'Use environment variables: password = os.environ.get("DB_PASSWORD")',
                    'example_attack': 'Attacker reads source code to extract credentials',
                    'impact': 'Unauthorized access, data breach, account takeover'
                },
                'path_traversal': {
                    'cwe': 'CWE-22',
                    'severity': 'High',
                    'patterns': [
                        r"open\(.*['\"].*\+",
                        r"open\(.*f['\"].*\{.*\}",
                        r"os\.path\.join\(.*['\"].*\+",
                        r"Path\(.*['\"].*\+",
                        r"file_get_contents\(.*['\"].*\+",
                        r"fs\.readFile(?:Sync)?\(.*['\"].*\+"
                    ],
                    'description': 'Path Traversal: User-controlled path data used in file operations',
                    'fix': 'Resolve with os.path.abspath(), then verify the resolved path starts with the expected base directory prefix before opening it.',
                    'example_attack': "../../../etc/passwd",
                    'impact': 'Unauthorized file access, data disclosure'
                },
                'xss': {
                    'cwe': 'CWE-79',
                    'severity': 'High',
                    'patterns': [
                        r"render_template.*input",
                        r"return.*\+\s*input",
                        r"innerHTML\s*=.*input"
                    ],
                    'description': 'Cross-Site Scripting (XSS): User input rendered in HTML',
                    'fix': 'Escape HTML output: return escape(input)',
                    'example_attack': '<script>alert(document.cookie)</script>',
                    'impact': 'Session hijacking, defacement, phishing'
                }
            },
            'javascript': {
                'xss': {
                    'cwe': 'CWE-79',
                    'severity': 'High',
                    'patterns': [
                        r"\$\{",
                        r"\$\{.*\}",
                        r"\$\{.*query",
                        r"\$\{.*req\.",
                        r"res\.send\s*\(`[^`]*\$\{",
                        r"res\.send\s*\(.*query",
                        r"\.innerHTML\s*=\s*",
                        r"document\.write\s*\(",
                        r"eval\s*\("
                    ],
                    'description': 'XSS: User input directly inserted into HTML without sanitization',
                    'fix': 'Use textContent or sanitize: DOMPurify.sanitize(input)',
                    'example_attack': '<img src=x onerror=alert(1)>',
                    'impact': 'Session hijacking, defacement, phishing'
                },
                'hardcoded_credentials': {
                    'cwe': 'CWE-798',
                    'severity': 'Critical',
                    'patterns': [
                        r"(?<!['\"#//])(?<!getenv)(?<!environ)(?<!env\.)(?<!process\.env)^[ \t]*databasePassword\s*[:=]\s*['\"][^'\"]+['\"]",
                        r"(?<!['\"#//])(?<!getenv)(?<!environ)(?<!env\.)(?<!process\.env)^[ \t]*apiKey\s*[:=]\s*['\"][^'\"]+['\"]",
                        r"(?<!['\"#//])(?<!getenv)(?<!environ)(?<!env\.)(?<!process\.env)^[ \t]*jwtSecret\s*[:=]\s*['\"][^'\"]+['\"]",
                        r"(?<!['\"#//])(?<!getenv)(?<!environ)(?<!env\.)(?<!process\.env)^[ \t]*secret\s*[:=]\s*['\"][^'\"]+['\"]",
                        r"(?<!['\"#//])(?<!getenv)(?<!environ)(?<!env\.)(?<!process\.env)^[ \t]*password\s*[:=]\s*['\"][^'\"]+['\"]",
                        r"(?<!['\"#//])(?<!getenv)(?<!environ)(?<!env\.)(?<!process\.env)^[ \t]*awsAccessKeyId\s*[:=]\s*['\"][^'\"]+['\"]",
                        r"(?<!['\"#//])(?<!getenv)(?<!environ)(?<!env\.)(?<!process\.env)^[ \t]*awsSecretAccessKey\s*[:=]\s*['\"][^'\"]+['\"]",
                        r"(?<!['\"#//])(?<!getenv)(?<!environ)(?<!env\.)(?<!process\.env)^[ \t]*databaseUser\s*[:=]\s*['\"][^'\"]+['\"]"
                    ],
                    'description': 'Hardcoded credentials found in code',
                    'fix': 'Use environment variables: process.env.DB_PASSWORD',
                    'example_attack': 'Attacker reads source code to extract credentials',
                    'impact': 'Unauthorized access, data breach, account takeover'
                }
            }
        }

    def _line_span_for_match(self, code, match):
        line = code.count('\n', 0, match.start()) + 1
        end_line = line + code[match.start():match.end()].count('\n')
        return line, end_line

    def _lines_for_span(self, line, end_line):
        return list(range(line, end_line + 1))

    def _build_snippet(self, code_lines, line, end_line, context=0):
        if context <= 0:
            return ""

        start = max(1, line - context)
        end = min(len(code_lines), end_line + context)
        return "".join(
            f"{line_no}: {code_lines[line_no - 1]}"
            for line_no in range(start, end + 1)
        ).rstrip("\n")

    def _has_safe_parameterized_argument(self, call_text):
        try:
            parsed = ast.parse(call_text.strip(), mode='eval')
            node = parsed.body
        except SyntaxError:
            try:
                parsed = ast.parse(call_text.strip())
                node = parsed.body[0].value if parsed.body and isinstance(parsed.body[0], ast.Expr) else None
            except SyntaxError:
                return False

        if not isinstance(node, ast.Call) or len(node.args) < 2:
            return False

        return isinstance(node.args[1], (ast.Tuple, ast.List, ast.Dict))

    def _find_call_text(self, code, start_pos):
        open_pos = code.find('(', start_pos)
        if open_pos == -1:
            return ""

        depth = 0
        in_string = None
        escaped = False
        for idx in range(open_pos, len(code)):
            char = code[idx]
            if in_string:
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == in_string:
                    in_string = None
                continue
            if char in ('"', "'"):
                in_string = char
            elif char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth == 0:
                    prefix_start = max(0, code.rfind('\n', 0, start_pos) + 1)
                    return code[prefix_start:idx + 1]
        return ""

    def _is_safe_parameterized_execute(self, code, match):
        for execute_match in re.finditer(r"(?:cursor\.)?(?:execute|executemany)\s*\(", code, re.IGNORECASE):
            if execute_match.start() > match.start():
                break
            call_text = self._find_call_text(code, execute_match.start())
            if call_text and execute_match.start() <= match.start() <= execute_match.start() + len(call_text):
                return self._has_safe_parameterized_argument(call_text)
        return False

    def _has_nearby_path_traversal_guard(self, code_lines, line_number):
        guard_patterns = (
            r"os\.path\.basename\s*\(",
            r"\.replace\s*\(",
            r"validate",
            r"validation",
            r"sanitize",
            r"allowlist",
            r"allowed",
            r"os\.path\.abspath\s*\(",
            r"os\.path\.realpath\s*\(",
            r"os\.path\.normpath\s*\(",
            r"os\.path\.commonpath\s*\(",
            r"\.startswith\s*\(",
            r"\.is_relative_to\s*\(",
        )
        start = max(1, line_number - 3)
        preceding_context = ''.join(code_lines[start - 1:line_number - 1])
        return any(re.search(pattern, preceding_context, re.IGNORECASE) for pattern in guard_patterns)

    def _make_finding(self, vuln_info, vuln_type, line, end_line, lines, confidence, snippet=""):
        return {
            'cwe_id': vuln_info['cwe'],
            'severity': vuln_info['severity'],
            'description': vuln_info['description'],
            'suggestion': vuln_info['fix'],
            'vulnerability_type': vuln_type.replace('_', ' ').title(),
            'confidence': confidence,
            'line': line,
            'end_line': end_line,
            'lines': lines,
            'snippet': snippet,
            'example_attack': vuln_info.get('example_attack', 'N/A'),
            'impact': vuln_info.get('impact', 'N/A')
        }

    def pattern_based_detection(self, code, language, lines=None, context=0):
        vulnerabilities = []
        patterns = self.patterns.get(language, {})
        code_lines = lines if lines is not None else code.splitlines(True)

        for vuln_type, vuln_info in patterns.items():
            if vuln_type == 'sql_injection':
                findings_by_line = {}
                for pattern in vuln_info['patterns']:
                    for match in re.finditer(pattern, code, re.IGNORECASE | re.DOTALL):
                        if self._is_safe_parameterized_execute(code, match):
                            continue
                        line, end_line = self._line_span_for_match(code, match)
                        if line not in findings_by_line:
                            findings_by_line[line] = self._make_finding(
                                vuln_info,
                                vuln_type,
                                line,
                                end_line,
                                self._lines_for_span(line, end_line),
                                0.75,
                                self._build_snippet(code_lines, line, end_line, context)
                            )
                        else:
                            findings_by_line[line]['confidence'] = min(0.95, findings_by_line[line]['confidence'] + 0.05)
                            findings_by_line[line]['end_line'] = max(findings_by_line[line]['end_line'], end_line)
                            findings_by_line[line]['lines'] = self._lines_for_span(line, findings_by_line[line]['end_line'])
                vulnerabilities.extend(findings_by_line.values())
                continue

            matched_patterns = set()
            matching_lines = set()
            for pattern in vuln_info['patterns']:
                for line_number, line in enumerate(code_lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        if vuln_type == 'path_traversal' and self._has_nearby_path_traversal_guard(code_lines, line_number):
                            continue
                        matched_patterns.add(pattern)
                        matching_lines.add(line_number)

            if matching_lines:
                match_count = len(matched_patterns)
                confidence = min(0.95, 0.7 + (match_count * 0.05))
                sorted_lines = sorted(matching_lines)
                line = sorted_lines[0]

                vulnerabilities.append(self._make_finding(
                    vuln_info,
                    vuln_type,
                    line,
                    line,
                    sorted_lines,
                    confidence,
                    self._build_snippet(code_lines, line, line, context)
                ))

        return vulnerabilities

    def _node_contains_call(self, node):
        return any(isinstance(child, ast.Call) for child in ast.walk(node))

    def _joined_str_contains_sql(self, node):
        sql_keywords = ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION')
        literal_text = ''.join(value.value for value in node.values if isinstance(value, ast.Constant) and isinstance(value.value, str))
        return any(keyword in literal_text.upper() for keyword in sql_keywords)

    def _call_name(self, func):
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return ''

    def ast_sql_injection_detection(self, file_path, lines, context=0):
        with tempfile.NamedTemporaryFile() as compiled_file:
            try:
                py_compile.compile(file_path, cfile=compiled_file.name, doraise=True)
            except py_compile.PyCompileError:
                return []

        code = ''.join(lines)
        tree = ast.parse(code, filename=file_path)
        sql_info = self.patterns['python']['sql_injection']
        findings = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr) and self._joined_str_contains_sql(node) and self._node_contains_call(node):
                line = getattr(node, 'lineno', 1)
                end_line = getattr(node, 'end_lineno', line)
                findings[line] = self._make_finding(sql_info, 'sql_injection', line, end_line, self._lines_for_span(line, end_line), 0.85, self._build_snippet(lines, line, end_line, context))
            elif isinstance(node, ast.Call) and self._call_name(node.func) in {'execute', 'executemany'}:
                if len(node.args) > 1 and isinstance(node.args[1], (ast.Tuple, ast.List, ast.Dict)):
                    continue
                for arg in node.args:
                    if isinstance(arg, ast.JoinedStr):
                        line = getattr(node, 'lineno', getattr(arg, 'lineno', 1))
                        end_line = getattr(node, 'end_lineno', getattr(arg, 'end_lineno', line))
                        findings[line] = self._make_finding(sql_info, 'sql_injection', line, end_line, self._lines_for_span(line, end_line), 0.9, self._build_snippet(lines, line, end_line, context))
                        break

        return list(findings.values())

    def _merge_findings(self, regex_findings, ast_findings):
        merged = {finding['line']: finding for finding in regex_findings}
        for finding in ast_findings:
            if finding['line'] not in merged:
                merged[finding['line']] = finding
        return list(merged.values())

    def analyze_paths(self, code, language, vulnerabilities):
        paths = []
        for vuln in vulnerabilities:
            vuln_type = vuln.get('vulnerability_type', '').lower()

            if 'sql' in vuln_type:
                paths.append({
                    'source': 'User Input → HTTP Request Parameter',
                    'sink': 'Database Query Execution',
                    'flow': 'User input flows directly to SQL query without sanitization',
                    'remediation': 'Use parameterized queries to break the attack path',
                    'attack_chain': 'Input → Query Construction → Database Execution → Data Exposure'
                })
            elif 'hardcoded' in vuln_type:
                paths.append({
                    'source': 'Hardcoded value in source code',
                    'sink': 'Authentication/API Call',
                    'flow': 'Credentials exposed in code → Attacker can read them',
                    'remediation': 'Move credentials to environment variables',
                    'attack_chain': 'Code Access → Credential Extraction → Unauthorized Access'
                })
            elif 'command' in vuln_type:
                paths.append({
                    'source': 'User Input → Form/URL Parameter',
                    'sink': 'System Command Execution',
                    'flow': 'User input passed to shell command without validation',
                    'remediation': 'Use subprocess with argument list, avoid shell=True',
                    'attack_chain': 'Input Injection → Shell Execution → System Compromise'
                })
            elif 'path' in vuln_type:
                paths.append({
                    'source': 'User Input → File Path Parameter',
                    'sink': 'File System Operation',
                    'flow': 'User input used to construct file path without validation',
                    'remediation': 'Validate and sanitize input, use allowlist',
                    'attack_chain': 'Path Injection → Directory Traversal → File Access'
                })
            elif 'xss' in vuln_type:
                paths.append({
                    'source': 'User Input → HTTP Request Parameter',
                    'sink': 'HTML Rendering',
                    'flow': 'User input rendered directly in HTML without sanitization',
                    'remediation': 'Escape HTML output or use CSP headers',
                    'attack_chain': 'Input Injection → HTML Rendering → Script Execution'
                })
        return paths

    def prioritize_vulnerabilities(self, vulnerabilities):
        severity_order = {'Critical': 9, 'High': 7, 'Medium': 5, 'Low': 3}
        for v in vulnerabilities:
            base_score = severity_order.get(v['severity'], 5)
            confidence_boost = v.get('confidence', 0.7) * 0.5
            v['priority_score'] = min(10, base_score + confidence_boost)
            v['priority_level'] = v['severity']
            v['exploitability'] = 'High' if v['confidence'] > 0.85 else 'Medium'
        return sorted(vulnerabilities, key=lambda x: x['priority_score'], reverse=True)

    def analyze_file(self, file_path, context=0, max_file_size_kb=500, benchmark=False):
        start_time = time.perf_counter()
        print(f"Analyzing: {file_path}")

        file_size_kb = os.path.getsize(file_path) / 1024
        if file_size_kb > max_file_size_kb:
            warning = f"Skipping {file_path}: file size {file_size_kb:.1f} KB exceeds {max_file_size_kb} KB"
            print(f"⚠️ {warning}")
            return {"error": warning, "skipped": True}

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                code = ''.join(lines)
        except Exception as e:
            return {"error": str(e)}

        ext = Path(file_path).suffix.lower()
        language = self.LANGUAGE_EXTENSIONS.get(ext, 'unknown')

        if language == 'unknown':
            return {"error": f"Unsupported language: {ext}"}

        vulnerabilities = self.pattern_based_detection(code, language, lines, context)
        if language == 'python':
            ast_findings = self.ast_sql_injection_detection(file_path, lines, context)
            vulnerabilities = self._merge_findings(vulnerabilities, ast_findings)
        vulnerabilities = self.prioritize_vulnerabilities(vulnerabilities)

        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for v in vulnerabilities:
            severity_counts[v['severity']] += 1

        path_analysis = self.analyze_paths(code, language, vulnerabilities)

        avg_confidence = sum(v.get('confidence', 0.7) for v in vulnerabilities) / len(vulnerabilities) if vulnerabilities else 1.0
        false_positive_rate = 1 - avg_confidence

        elapsed = time.perf_counter() - start_time
        if benchmark:
            print(f"⏱️ {file_path}: {elapsed:.4f}s")

        return {
            "file": os.path.basename(file_path),
            "file_path": file_path,
            "language": language,
            "analysis_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "critical": severity_counts['Critical'],
                "high": severity_counts['High'],
                "medium": severity_counts['Medium'],
                "low": severity_counts['Low']
            },
            "vulnerabilities": vulnerabilities,
            "path_analysis": path_analysis,
            "metrics": {
                "average_confidence": avg_confidence,
                "false_positive_rate": false_positive_rate,
                "security_score": max(0, 10 - (len(vulnerabilities) * 1.5)),
                "scan_time_seconds": elapsed
            }
        }

    def _sarif_level_for_severity(self, severity):
        severity_levels = {
            'Critical': 'error',
            'High': 'warning',
            'Medium': 'note',
            'Low': 'note',
        }
        return severity_levels.get(severity, 'warning')

    def _sarif_findings(self, results):
        if 'files' in results:
            for file_uri, file_results in results.get('files', {}).items():
                for vuln in file_results.get('vulnerabilities', []):
                    yield file_results.get('file_path') or file_uri, vuln
            return

        file_uri = results.get('file_path') or results.get('file') or 'Unknown'
        for vuln in results.get('vulnerabilities', []):
            yield file_uri, vuln

    def _generate_sarif_report(self, results):
        rules = {}
        sarif_results = []

        for file_uri, vuln in self._sarif_findings(results):
            cwe_id = vuln.get('cwe_id', 'Unknown')
            severity = vuln.get('severity', 'Unknown')
            description = vuln.get('description', 'N/A')
            suggestion = vuln.get('suggestion', 'N/A')
            start_line = int(vuln.get('line') or 1)
            end_line = int(vuln.get('end_line') or start_line)
            snippet = vuln.get('snippet', '')

            if cwe_id not in rules:
                rules[cwe_id] = {
                    'id': cwe_id,
                    'name': vuln.get('vulnerability_type', cwe_id),
                    'shortDescription': {
                        'text': vuln.get('vulnerability_type', cwe_id)
                    },
                    'fullDescription': {
                        'text': description
                    },
                    'help': {
                        'text': suggestion
                    },
                    'properties': {
                        'tags': [cwe_id],
                        'security-severity': str(vuln.get('priority_score', '')),
                        'severity': severity
                    }
                }

            sarif_results.append({
                'ruleId': cwe_id,
                'level': self._sarif_level_for_severity(severity),
                'message': {
                    'text': description
                },
                'locations': [
                    {
                        'physicalLocation': {
                            'artifactLocation': {
                                'uri': file_uri
                            },
                            'region': {
                                'startLine': start_line,
                                'endLine': end_line,
                                'snippet': {
                                    'text': snippet
                                }
                            }
                        }
                    }
                ],
                'properties': {
                    'severity': severity,
                    'fix': suggestion,
                    'confidence': vuln.get('confidence'),
                    'vulnerability_type': vuln.get('vulnerability_type'),
                    'impact': vuln.get('impact')
                }
            })

        report = {
            '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
            'version': '2.1.0',
            'runs': [
                {
                    'tool': {
                        'driver': {
                            'name': 'VulnPath-AI',
                            'informationUri': 'https://github.com/',
                            'rules': list(rules.values())
                        }
                    },
                    'results': sarif_results
                }
            ]
        }
        return json.dumps(report, indent=2)

    def generate_report(self, file_path, findings, format="markdown"):
        if format == "json":
            return json.dumps(findings, indent=2)
        if format == "sarif":
            return self._generate_sarif_report(findings)

        vulns = findings.get('vulnerabilities', [])
        summary = findings.get('summary', {})
        paths = findings.get('path_analysis', [])
        metrics = findings.get('metrics', {})

        report_lines = []
        report_lines.append("# 🛡️ VulnPath-AI Security Analysis Report")
        report_lines.append("")
        report_lines.append("## 📋 Summary")
        report_lines.append(f"- **File:** {findings.get('file', 'Unknown')}")
        report_lines.append(f"- **Language:** {findings.get('language', 'Unknown')}")
        report_lines.append(f"- **Analysis Date:** {findings.get('analysis_date', 'Unknown')}")
        report_lines.append(f"- **Total Vulnerabilities:** {summary.get('total_vulnerabilities', 0)}")
        report_lines.append(f"- **Critical:** {summary.get('critical', 0)}")
        report_lines.append(f"- **High:** {summary.get('high', 0)}")
        report_lines.append(f"- **Medium:** {summary.get('medium', 0)}")
        report_lines.append(f"- **Low:** {summary.get('low', 0)}")
        report_lines.append("")
        report_lines.append(f"## 🛡️ Security Score: {metrics.get('security_score', 10):.1f}/10")
        report_lines.append("")
        report_lines.append("## 📊 Performance Metrics")
        report_lines.append(f"- **Average Confidence:** {metrics.get('average_confidence', 0):.1%}")
        report_lines.append(f"- **False Positive Rate:** {metrics.get('false_positive_rate', 0):.1%}")
        report_lines.append(f"- **Scan Time:** {metrics.get('scan_time_seconds', 0):.4f} seconds")
        report_lines.append("")
        report_lines.append("## 🔍 Detailed Findings")
        report_lines.append("")

        if not vulns:
            report_lines.append("✅ No vulnerabilities found! Your code looks secure.")
        else:
            for i, v in enumerate(vulns, 1):
                report_lines.append(f"### {i}. {v.get('vulnerability_type', 'Unknown Vulnerability')}")
                report_lines.append(f"- **CWE:** {v.get('cwe_id', 'Unknown')}")
                if v.get('end_line', v.get('line')) != v.get('line'):
                    report_lines.append(f"- **Lines:** {v.get('line')}-{v.get('end_line')}")
                else:
                    report_lines.append(f"- **Line:** {v.get('line', 'Unknown')}")
                report_lines.append(f"- **Severity:** {v.get('severity', 'Unknown')} (Priority Score: {v.get('priority_score', 5):.1f}/10)")
                report_lines.append(f"- **Confidence:** {v.get('confidence', 0.85):.1%}")
                report_lines.append(f"- **Exploitability:** {v.get('exploitability', 'Medium')}")
                report_lines.append(f"- **Description:** {v.get('description', 'N/A')}")
                report_lines.append(f"- **Fix Suggestion:** {v.get('suggestion', 'N/A')}")
                report_lines.append("")
                if v.get('snippet'):
                    report_lines.append("#### 📄 Code Context")
                    report_lines.append("```")
                    report_lines.append(v.get('snippet'))
                    report_lines.append("```")
                    report_lines.append("")

                report_lines.append("#### 💥 Example Attack")
                report_lines.append("```")
                report_lines.append(f"{v.get('example_attack', 'N/A')}")
                report_lines.append("```")
                report_lines.append("")
                report_lines.append("#### 💰 Business Impact")
                report_lines.append(f"{v.get('impact', 'N/A')}")
                report_lines.append("")
                report_lines.append("#### 🔗 Attack Path Analysis")

                matched_path = None
                vuln_type = v.get('vulnerability_type', '').lower()
                for path in paths:
                    if 'sql' in vuln_type and 'sql' in str(path).lower():
                        matched_path = path
                        break
                    elif 'hardcoded' in vuln_type and 'hardcoded' in str(path).lower():
                        matched_path = path
                        break
                    elif 'command' in vuln_type and 'command' in str(path).lower():
                        matched_path = path
                        break
                    elif 'path' in vuln_type and 'path' in str(path).lower():
                        matched_path = path
                        break
                    elif 'xss' in vuln_type and 'xss' in str(path).lower():
                        matched_path = path
                        break

                if matched_path:
                    report_lines.append(f"- **Source:** {matched_path.get('source', 'Unknown')}")
                    report_lines.append(f"- **Sink:** {matched_path.get('sink', 'Unknown')}")
                    report_lines.append(f"- **Flow:** {matched_path.get('flow', 'Unknown')}")
                    report_lines.append(f"- **Attack Chain:** {matched_path.get('attack_chain', 'Unknown')}")
                    report_lines.append(f"- **Remediation:** {matched_path.get('remediation', 'Unknown')}")
                else:
                    report_lines.append("- Path analysis available in full report")

                report_lines.append("")

        report_lines.append("")
        report_lines.append("## 📊 Vulnerability Summary Table")
        report_lines.append("| # | CWE | Vulnerability | Location | Severity | Priority | Confidence |")
        report_lines.append("|---|-----|---------------|----------|----------|----------|------------|")
        for i, v in enumerate(vulns, 1):
            line_numbers = v.get('lines', [])
            location = ', '.join(f"{findings.get('file', 'Unknown')}:{line}" for line in line_numbers) if line_numbers else findings.get('file', 'Unknown')
            report_lines.append(f"| {i} | {v.get('cwe_id', 'Unknown')} | {v.get('vulnerability_type', 'Unknown')} | {location} | {v.get('severity', 'Unknown')} | {v.get('priority_score', 5):.1f}/10 | {v.get('confidence', 0.85):.1%} |")

        report_lines.append("")
        report_lines.append("## 🎯 Recommendation Summary")
        report_lines.append("1. **Immediate Fixes:** Address all Critical vulnerabilities first")
        report_lines.append("2. **High Priority:** Fix High severity issues next")
        report_lines.append("3. **Low Priority:** Review Medium and Low findings")
        report_lines.append("4. **Best Practices:** Implement security scanning in CI/CD pipeline")
        report_lines.append("")
        report_lines.append("## 📈 False Positive Analysis")
        report_lines.append(f"- **Total Findings:** {len(vulns)}")
        report_lines.append(f"- **High Confidence (>90%):** {sum(1 for v in vulns if v.get('confidence', 0) > 0.9)}")
        report_lines.append(f"- **Medium Confidence (70-90%):** {sum(1 for v in vulns if 0.7 <= v.get('confidence', 0) <= 0.9)}")
        report_lines.append(f"- **Low Confidence (<70%):** {sum(1 for v in vulns if v.get('confidence', 0) < 0.7)}")
        report_lines.append("")
        report_lines.append("---")
        report_lines.append("*Report generated by VulnPath-AI - Security vulnerability detection with AI-powered pattern matching*")

        return "\n".join(report_lines)


def build_ai_prompt(target_path, interactive=False):
    script_dir = Path(__file__).resolve().parent
    system_prompt_path = script_dir / "SYSTEM_PROMPT.md"

    with open(system_prompt_path, 'r', encoding='utf-8') as f:
        system_prompt = f.read()

    with open(target_path, 'r', encoding='utf-8') as f:
        target_code = f.read()

    header = """
╔══════════════════════════════════════════════════════╗
║  VulnPath-AI — GPT-5.6 Analysis Mode               ║
╚══════════════════════════════════════════════════════╝

Step 1: Open ChatGPT or Codex (chat.openai.com)
Step 2: Paste the SYSTEM_PROMPT.md content below
Step 3: Paste the target code below
Step 4: GPT-5.6 will analyze it with attack paths, CVSS, business impact
""".strip("\n")

    sections = [
        header,
        "─── SYSTEM PROMPT ───\n" + system_prompt,
        "─── CODE TO ANALYZE ───\n" + target_code,
        "── END ──",
    ]

    if interactive:
        prompts = [
            "Press Enter to show the GPT-5.6 analysis instructions...",
            "Press Enter to show SYSTEM_PROMPT.md...",
            "Press Enter to show the target code...",
            "Press Enter to finish...",
        ]
        for prompt, section in zip(prompts, sections):
            input(prompt)
            print(section)
            print()
    else:
        print("\n\n".join(sections))


def main():
    import argparse

    parser = argparse.ArgumentParser(description='VulnPath-AI - Advanced Security Analyzer')
    parser.add_argument('path', help='File or directory path')
    parser.add_argument('--dir', action='store_true', help='Analyze directory')
    parser.add_argument('--recursive', '-r', action='store_true', help='Recursive scan')
    parser.add_argument('--format', '-f', choices=['json', 'markdown', 'sarif'], default='markdown')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--ai', '-a', action='store_true', help='Generate a prompt for GPT-5.6 analysis instead of regex scanning')
    parser.add_argument('--interactive', action='store_true', help='Generate the GPT-5.6 prompt step by step with prompts')
    parser.add_argument('--skip-dirs', default='venv,.venv,env,node_modules,__pycache__,.git,.tox,dist,build', help='Comma-separated directory names to skip during directory scans (default: venv,.venv,env,node_modules,__pycache__,.git,.tox,dist,build)')
    parser.add_argument('--ext', default='.py,.js,.jsx,.ts,.tsx,.java,.php,.rb,.go,.html', help='Comma-separated file extensions to include during directory scans (default: .py,.js,.jsx,.ts,.tsx,.java,.php,.rb,.go,.html)')
    parser.add_argument('--context', type=int, default=0, help='Include N lines of surrounding source code in Markdown and JSON findings (default: 0)')
    parser.add_argument('--max-file-size', type=int, default=500, help='Skip files larger than this size in KB (default: 500)')
    parser.add_argument('--benchmark', action='store_true', help='Print per-file scan time and total scan time')

    args = parser.parse_args()
    if args.ai or args.interactive:
        if os.path.isdir(args.path):
            parser.error('--ai/--interactive mode requires a single target code file')
        build_ai_prompt(args.path, interactive=args.interactive)
        return

    analyzer = VulnPathAI()
    skip_dirs = {name.strip() for name in args.skip_dirs.split(',') if name.strip()}
    total_start = time.perf_counter()

    def should_skip_path(candidate, root=None, gitignore_spec=None):
        candidate_path = Path(candidate)
        if any(part in skip_dirs for part in candidate_path.parts):
            return True
        if root and gitignore_spec:
            relative_path = candidate_path.relative_to(root).as_posix()
            return gitignore_spec.match_file(relative_path)
        return False

    if os.path.isdir(args.path):
        print(f"📁 Scanning directory: {args.path}")
        all_results = {}

        path = Path(args.path)
        gitignore_spec = None
        gitignore_path = path / '.gitignore'
        if gitignore_path.is_file():
            if pathspec is None:
                print("⚠️ pathspec is not installed; ignoring .gitignore rules and using --skip-dirs only")
            else:
                with gitignore_path.open(encoding='utf-8') as gitignore_file:
                    gitignore_spec = pathspec.PathSpec.from_lines('gitwildmatch', gitignore_file)
                print("📄 Using .gitignore rules")
        extensions = {
            ext if ext.startswith('.') else f'.{ext}'
            for ext in (item.strip().lower() for item in args.ext.split(','))
            if ext
        }
        unsupported_extensions = extensions - analyzer.LANGUAGE_EXTENSIONS.keys()
        if unsupported_extensions:
            parser.error(f"Unsupported extension(s): {', '.join(sorted(unsupported_extensions))}")

        for ext in extensions:
            for file in path.rglob(f'*{ext}') if args.recursive else path.glob(f'*{ext}'):
                if should_skip_path(file, root=path, gitignore_spec=gitignore_spec):
                    continue
                all_results[str(file)] = analyzer.analyze_file(str(file), context=args.context, max_file_size_kb=args.max_file_size, benchmark=args.benchmark)

        if args.format == 'json':
            combined_report = json.dumps(all_results, indent=2)
        elif args.format == 'sarif':
            combined_report = analyzer._generate_sarif_report({'files': all_results})
        else:
            combined_report_lines = []
            combined_report_lines.append("# 🛡️ VulnPath-AI - Full Directory Scan Report")
            combined_report_lines.append("")
            combined_report_lines.append(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            combined_report_lines.append(f"**Directory:** {args.path}")
            combined_report_lines.append("")

            for file_path, results in all_results.items():
                combined_report_lines.append(analyzer.generate_report(file_path, results, 'markdown'))
                combined_report_lines.append("")
                combined_report_lines.append("---")
                combined_report_lines.append("")

            combined_report = "\n".join(combined_report_lines)

        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(combined_report)
            print(f"\n✅ Report saved to {args.output}")
        else:
            print(combined_report)
        if args.benchmark:
            print(f"⏱️ Total scan time: {time.perf_counter() - total_start:.4f}s")

    else:
        results = analyzer.analyze_file(args.path, context=args.context, max_file_size_kb=args.max_file_size, benchmark=args.benchmark)
        report = analyzer.generate_report(args.path, results, args.format)
        print(report)

        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\n✅ Report saved to {args.output}")
        if args.benchmark:
            print(f"⏱️ Total scan time: {time.perf_counter() - total_start:.4f}s")

if __name__ == "__main__":
    main()
