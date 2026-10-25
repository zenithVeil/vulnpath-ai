#!/usr/bin/env python
import yaml

# Read the YAML file as raw text
with open('d:\\vulnpath-ai\\rules\\python_ai_agent.yaml', 'r') as f:
    content = f.read()

# Find the position after yaml_ssrf rule (after the 'impact' line) and before yaml_weak_crypto
# Insert the new httpx and aiohttp SSRF rules

# The new rules in correct YAML format - patterns use \\\\. which YAML parses as \\. which regex parses as \.
# We need the YAML file to contain: httpx\\.(get|post|put|delete) 
# (PyYAML will parse \\\\ as \\, giving regex \. = literal dot)

new_rules = '''    - id: yaml_httpx_ssrf
  name: Agent Httpx SSRF
  cwe: CWE-918
  severity: High
  patterns:
  - httpx\\\\.(get|post|put|delete)\\\\s*\\([a-zA-Z_\\\\w]*\\\\s*\\)\n  - httpx\\\\.(get|post|put|delete)\\\\s*\\(.*[\\\"\\\\'].*\\\\+\n  suggestion: Validate the URL against an allowlist of hosts before fetching.\n  impact: Unauthorized access to internal services, data exposure
    - id: yaml_aiohttp_ssrf
  name: Agent Aiohttp SSRF
  cwe: CWE-918
  severity: High
  patterns:
  - aiohttp\\\\.(get|post|put|delete)\\\\s*\\([a-zA-Z_\\\\w]*\\\\s*\\)\n  - aiohttp\\\\.(get|post|put|delete)\\\\s*\\(.*[\\\"\\\\'].*\\\\+\n  suggestion: Validate the URL against an allowlist of hosts before fetching.\n  impact: Unauthorized access to internal services, data exposure'''

# Insert before yaml_weak_crypto
if '- id: yaml_weak_crypto' in content:
    new_content = content.replace('- id: yaml_weak_crypto', new_rules + '\n- id: yaml_weak_crypto', 1)
    with open('d:\\vulnpath-ai\\rules\\python_ai_agent.yaml', 'w') as f:
        f.write(new_content)
    print('Successfully inserted new SSRF rules')
else:
    print('ERROR: Could not find yaml_weak_crypto marker')