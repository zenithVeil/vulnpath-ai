import yaml

# Test how _load_yaml_rules would process the YAML
with open('d:/vulnpath-ai/rules/python_ai_agent.yaml') as f:
    data = yaml.safe_load(f)

# Simulate the _load_yaml_rules processing
rules_dict = {}
for item in data:
    rule_id = item.get('id', '')
    rules_dict[rule_id] = {
        'cwe': item.get('cwe'),
        'severity': item.get('severity'),
        'patterns': item.get('patterns', []),
        'suggestion': item.get('suggestion'),
        'impact': item.get('impact'),
        'name': item.get('name')
    }

# Show how rules would be loaded
for key, info in rules_dict.items():
    if 'ssrf' in key.lower() or 'weak_crypto' in key.lower():
        print(f"Rule: {key}")
        print(f"  CWE: {info['cwe']}")
        print(f"  Severity: {info['severity']}")
        print(f"  Patterns: {len(info['patterns'])} patterns")
        print(f"  Suggestion: {info['suggestion']}")
        print(f"  Impact: {info['impact']}")
        print()