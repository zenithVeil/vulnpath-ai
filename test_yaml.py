import yaml

data = yaml.safe_load(open('d:/vulnpath-ai/rules/python_ai_agent.yaml'))
print('Type:', type(data))
if isinstance(data, list):
    print('Length:', len(data))
    print('First item keys:', list(data[0].keys()) if data else 'empty')
    # Find yaml_ssrf
    for item in data:
        if item.get('id') == 'yaml_ssrf':
            print('Found yaml_ssrf:', item.get('name'))
        if item.get('id') == 'yaml_weak_crypto':
            print('Found yaml_weak_crypto:', item.get('name'))
elif isinstance(data, dict):
    print('Dict keys:', list(data.keys())[:5])
    for k, v in data.items():
        if 'ssrf' in k.lower():
            print(f'Found {k}:', v.get('name'))