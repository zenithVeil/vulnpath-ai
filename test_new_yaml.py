import yaml

# Test the new python_ai.yaml file
with open('d:/vulnpath-ai/rules/python_ai.yaml') as f:
    data = yaml.safe_load(f)

print('Type:', type(data))
print('Length:', len(data) if isinstance(data, list) else len(data))

# Show all rule IDs
if isinstance(data, list):
    for i, rule in enumerate(data):
        print(f"{i}: {rule.get('id', 'N/A')}: {rule.get('name', 'N/A')}")
    
    # Find the SSRF rules we added
    for rule in data:
        if 'httpx' in rule.get('id', '') or 'aiohttp' in rule.get('id', ''):
            print(f"\nFound SSRF rule: {rule.get('id')}: {rule.get('name')}")
            print(f"  CWE: {rule.get('cwe')}")
            print(f"  Severity: {rule.get('severity')}")
            print(f"  Patterns: {len(rule.get('patterns', []))}")
            print(f"  Suggestion: {rule.get('suggestion')}")
            print(f"  Impact: {rule.get('impact')}")