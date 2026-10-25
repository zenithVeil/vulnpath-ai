import yaml

with open('d:\\vulnpath-ai\\rules\\python_ai_agent.yaml', 'r') as f:
    rules = list(yaml.safe_load_all(f))

for i, r in enumerate(rules):
    if r and 'id' in r:
        print(f'Rule {i}: {r["id"]}')
        print(f'  CWE: {r.get("cwe", "N/A")}')
        print(f'  Severity: {r.get("severity", "N/A")}')
        print(f'  Patterns: {r.get("patterns", [])}')
        print()