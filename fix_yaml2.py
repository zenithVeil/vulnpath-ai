#!/usr/bin/env python
# Read the YAML file as raw bytes to avoid escaping issues
with open('d:\\vulnpath-ai\\rules\\python_ai_agent.yaml', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find the line number of '  impact: Unauthorized access to internal services, data exposure'
# This is line 78 (0-indexed: 77) in the original file
insert_after_idx = None
for i, line in enumerate(lines):
    if '  impact: Unauthorized access to internal services, data exposure' in line:
        insert_after_idx = i
        break

if insert_after_idx is None:
    print('Could not find insertion point')
    exit(1)

# New rules to insert - they go after line 78 (index 77) and before line 79
# The rules need to follow the exact same YAML format as existing rules
new_rules_lines = [
    '  - id: yaml_httpx_ssrf\n',
    '    name: Agent Httpx SSRF\n',
    '    cwe: CWE-918\n',
    '    severity: High\n',
    '    patterns:\n',
    '  - httpx\\\\.(get|post|put|delete)\\\\s*\\([a-zA-Z_][\\w]*\\s*\\)\n',
    '  - httpx\\\\.(get|post|put|delete)\\\\s*\\(.*[\"\\'].*\\+\n',
    '    suggestion: Validate the URL against an allowlist of hosts before fetching.\n',
    '    impact: Unauthorized access to internal services, data exposure\n',
    '  - id: yaml_aiohttp_ssrf\n',
    '    name: Agent Aiohttp SSRF\n',
    '    cwe: CWE-918\n',
    '    severity: High\n',
    '    patterns:\n',
    '  - aiohttp\\\\.(get|post|put|delete)\\\\s*\\([a-zA-Z_][\\w]*\\s*\\)\n',
    '  - aiohttp\\\\.(get|post|put|delete)\\\\s*\\(.*[\"\\'].*\\+\n',
    '    suggestion: Validate the URL against an allowlist of hosts before fetching.\n',
    '    impact: Unauthorized access to internal services, data exposure\n',
]

# Insert the new rules after the impact line
# The new rules consist of two rule entries (httpx and aiohttp), each with id, name, cwe, severity, patterns (2 patterns), suggestion, impact
# We need to insert them as a group, but YAML doesn't easily allow inserting multiple list items at once
# Instead, let's insert just the first rule and adjust

# Actually, let's insert the two new rules as part of the existing rule list
# The existing structure is: - id: ... \n  name: ... \n etc.
# We need to insert after line 78 (the impact line of yaml_ssrf)

# Insert the new httpx rule
httpx_rule = new_rules_lines[0:8]  # - id through impact of httpx rule

# Insert at position insert_after_idx + 1 (after the impact line)
new_lines = lines[:insert_after_idx + 1] + httpx_rule + ['  - id: yaml_aiohttp_ssrf\n'] + new_rules_lines[8:] + lines[insert_after_idx + 1:]

# Wait, this is getting complicated. Let me take a simpler approach.
# Let me just replace the whole file content properly.

# Actually, let me just write the complete correct YAML file.
# Read the original, find the insertion point, and insert properly.

# Let me try a different approach: replace the yaml_weak_crypto line with the new rules followed by yaml_weak_crypto

# Find '- id: yaml_weak_crypto'
weak_crypto_idx = None
for i, line in enumerate(lines):
    if '- id: yaml_weak_crypto' in line and i > 70:
        weak_crypto_idx = i
        break

if weak_crypto_idx is None:
    print('Could not find yaml_weak_crypto')
    exit(1)

# The new rules in the correct YAML format matching existing rules
# Each rule: - id: ... \n  name: ... \n  cwe: ... \n  severity: ... \n  patterns: \n  - ... \n  - ... \n  suggestion: ... \n  impact: ...
new_httpx_rule = '''  - id: yaml_httpx_ssrf
  name: Agent Httpx SSRF
  cwe: CWE-918
  severity: High
  patterns:
  - httpx\\\\.(get|post|put|delete)\\\\s*\\([a-zA-Z_][\\w]*\\s*\\)\n  - httpx\\\\.(get|post|put|delete)\\\\s*\\(.*[\"\\'].*\\+\n  suggestion: Validate the URL against an allowlist of hosts before fetching.\n  impact: Unauthorized access to internal services, data exposure'''

new_aiohttp_rule = '''  - id: yaml_aiohttp_ssrf
  name: Agent Aiohttp SSRF
  cwe: CWE-918
  severity: High
  patterns:
  - aiohttp\\\\.(get|post|put|delete)\\\\s*\\([a-zA-Z_][\\w]*\\s*\\)\n  - aiohttp\\\\.(get|post|put|delete)\\\\s*\\(.*[\"\\'].*\\+\n  suggestion: Validate the URL against an allowlist of hosts before fetching.\n  impact: Unauthorized access to internal services, data exposure'''

# Replace '- id: yaml_weak_crypto' with new rules + original line
# But we need to be careful about the leading spaces - the rules are list items with 2-space indent

# Actually, the lines in the file have 2-space indent for the list item properties
# - id: yaml_ssrf is at the top level of the list
# The properties inside have 2-space indent

# Let me just insert the new rules before '- id: yaml_weak_crypto'
# The new rules need to be list items starting with '  - id: '

insert_text = new_httpx_rule + '\n' + new_aiohttp_rule + '\n'

# Replace '- id: yaml_weak_crypto' with the insert text followed by the original line
lines[weak_crypto_idx] = insert_text + lines[weak_crypto_idx]

with open('d:\\vulnpath-ai\\rules\\python_ai_agent.yaml', 'w', encoding='utf-8') as f:
    f.writelines(lines)

print('YAML file updated')