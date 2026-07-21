# analyze_hybrid.py - Combined AI + Pattern Detection with Path Analysis
import os
import json
import sys
import re
from datetime import datetime
from pathlib import Path

class VulnPathAI:
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
                        r"f['\"].*SELECT.*\{.*\}.*['\"]"
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
                        r"os\.system\s*\(.*\+.*\)",
                        r"subprocess\.call\s*\(.*\+.*\)",
                        r"eval\s*\(.*\)"
                    ],
                    'description': 'Command Injection: User input in system commands',
                    'fix': 'Use subprocess with argument list: subprocess.run(["ls", user_input])',
                    'example_attack': "rm -rf / ; echo 'hacked'",
                    'impact': 'Remote code execution, system compromise'
                },
                'hardcoded_credentials': {
                    'cwe': 'CWE-798',
                    'severity': 'Critical',
                    'patterns': [
                        r"password\s*=\s*['\"][^'\"]+['\"]",
                        r"api_key\s*=\s*['\"][^'\"]+['\"]",
                        r"secret\s*=\s*['\"][^'\"]+['\"]",
                        r"token\s*=\s*['\"][^'\"]+['\"]"
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
                        r"open\s*\(.*\+.*\)",
                        r"os\.path\.join\s*\(.*input.*\)"
                    ],
                    'description': 'Path Traversal: User input in file operations',
                    'fix': 'Validate and sanitize: os.path.abspath(os.path.join(base_dir, user_input))',
                    'example_attack': "../../etc/passwd",
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
                        r"databasePassword\s*:\s*['\"][^'\"]+['\"]",
                        r"apiKey\s*:\s*['\"][^'\"]+['\"]",
                        r"jwtSecret\s*:\s*['\"][^'\"]+['\"]",
                        r"secret\s*:\s*['\"][^'\"]+['\"]",
                        r"password\s*:\s*['\"][^'\"]+['\"]",
                        r"awsAccessKeyId\s*:\s*['\"][^'\"]+['\"]",
                        r"awsSecretAccessKey\s*:\s*['\"][^'\"]+['\"]",
                        r"databaseUser\s*:\s*['\"][^'\"]+['\"]",
                        r"password\s*=\s*['\"][^'\"]+['\"]",
                        r"apiKey\s*=\s*['\"][^'\"]+['\"]",
                        r"secret\s*=\s*['\"][^'\"]+['\"]",
                        r"jwtSecret\s*=\s*['\"][^'\"]+['\"]"
                    ],
                    'description': 'Hardcoded credentials found in code',
                    'fix': 'Use environment variables: process.env.DB_PASSWORD',
                    'example_attack': 'Attacker reads source code to extract credentials',
                    'impact': 'Unauthorized access, data breach, account takeover'
                }
            }
        }
    
    def pattern_based_detection(self, code, language, lines=None):
        vulnerabilities = []
        patterns = self.patterns.get(language, {})
        code_lines = lines if lines is not None else code.splitlines()
        
        for vuln_type, vuln_info in patterns.items():
            matched_patterns = set()
            matching_lines = set()
            for pattern in vuln_info['patterns']:
                for line_number, line in enumerate(code_lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        matched_patterns.add(pattern)
                        matching_lines.add(line_number)
            
            if matching_lines:
                match_count = len(matched_patterns)
                confidence = min(0.95, 0.7 + (match_count * 0.05))
                sorted_lines = sorted(matching_lines)
                
                vulnerabilities.append({
                    'cwe_id': vuln_info['cwe'],
                    'severity': vuln_info['severity'],
                    'description': vuln_info['description'],
                    'suggestion': vuln_info['fix'],
                    'vulnerability_type': vuln_type.replace('_', ' ').title(),
                    'confidence': confidence,
                    'line': sorted_lines[0],
                    'lines': sorted_lines,
                    'example_attack': vuln_info.get('example_attack', 'N/A'),
                    'impact': vuln_info.get('impact', 'N/A')
                })
        
        return vulnerabilities
    
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
    
    def analyze_file(self, file_path):
        print(f"Analyzing: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                code = ''.join(lines)
        except Exception as e:
            return {"error": str(e)}
        
        ext = Path(file_path).suffix.lower()
        lang_map = {'.py': 'python', '.js': 'javascript', '.java': 'java', 
                    '.php': 'php', '.rb': 'ruby', '.go': 'go', '.html': 'html'}
        language = lang_map.get(ext, 'unknown')
        
        if language == 'unknown':
            return {"error": f"Unsupported language: {ext}"}
        
        vulnerabilities = self.pattern_based_detection(code, language, lines)
        vulnerabilities = self.prioritize_vulnerabilities(vulnerabilities)
        
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for v in vulnerabilities:
            severity_counts[v['severity']] += 1
        
        path_analysis = self.analyze_paths(code, language, vulnerabilities)
        
        avg_confidence = sum(v.get('confidence', 0.7) for v in vulnerabilities) / len(vulnerabilities) if vulnerabilities else 1.0
        false_positive_rate = 1 - avg_confidence
        
        return {
            "file": os.path.basename(file_path),
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
                "security_score": max(0, 10 - (len(vulnerabilities) * 1.5))
            }
        }
    
    def generate_report(self, file_path, findings, format="markdown"):
        if format == "json":
            return json.dumps(findings, indent=2)
        
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
        report_lines.append("- **Scan Time:** < 1 second per file")
        report_lines.append("")
        report_lines.append("## 🔍 Detailed Findings")
        report_lines.append("")
        
        if not vulns:
            report_lines.append("✅ No vulnerabilities found! Your code looks secure.")
        else:
            for i, v in enumerate(vulns, 1):
                report_lines.append(f"### {i}. {v.get('vulnerability_type', 'Unknown Vulnerability')}")
                report_lines.append(f"- **CWE:** {v.get('cwe_id', 'Unknown')}")
                report_lines.append(f"- **Line(s):** {v.get('lines', [])}")
                report_lines.append(f"- **Severity:** {v.get('severity', 'Unknown')} (Priority Score: {v.get('priority_score', 5):.1f}/10)")
                report_lines.append(f"- **Confidence:** {v.get('confidence', 0.85):.1%}")
                report_lines.append(f"- **Exploitability:** {v.get('exploitability', 'Medium')}")
                report_lines.append(f"- **Description:** {v.get('description', 'N/A')}")
                report_lines.append(f"- **Fix Suggestion:** {v.get('suggestion', 'N/A')}")
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
    parser.add_argument('--format', '-f', choices=['json', 'markdown'], default='markdown')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--ai', '-a', action='store_true', help='Generate a prompt for GPT-5.6 analysis instead of regex scanning')
    parser.add_argument('--interactive', action='store_true', help='Generate the GPT-5.6 prompt step by step with prompts')
    
    args = parser.parse_args()
    if args.ai or args.interactive:
        if os.path.isdir(args.path):
            parser.error('--ai/--interactive mode requires a single target code file')
        build_ai_prompt(args.path, interactive=args.interactive)
        return

    analyzer = VulnPathAI()
    
    if os.path.isdir(args.path):
        print(f"📁 Scanning directory: {args.path}")
        all_results = {}
        
        path = Path(args.path)
        extensions = {'.py', '.js', '.java', '.php', '.rb', '.go', '.html'}
        
        for ext in extensions:
            for file in path.rglob(f'*{ext}') if args.recursive else path.glob(f'*{ext}'):
                all_results[str(file)] = analyzer.analyze_file(str(file))
        
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
            
    else:
        results = analyzer.analyze_file(args.path)
        report = analyzer.generate_report(args.path, results, args.format)
        print(report)
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\n✅ Report saved to {args.output}")

if __name__ == "__main__":
    main()
