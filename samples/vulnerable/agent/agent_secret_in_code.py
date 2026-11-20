# Vulnerable fixture: hardcoded API-key style secrets (synthetic only)
OPENAI_API_KEY = "sk-test-fake-openai-key-for-fixture-only"
ANTHROPIC_API_KEY = "sk-ant-test-fake-key-for-fixture-only"
API_KEY = "example-only-not-a-real-api-key"


def get_client():
    # Fix suggestion: load secrets from environment variables or a secrets manager
    return OPENAI_API_KEY
