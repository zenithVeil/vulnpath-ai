# Vulnerable: hardcoded OpenAI/Anthropic/API keys style secrets
OPENAI_API_KEY = "sk-1234567890abcdef"
ANTHROPIC_API_KEY = "sk-ant-1234567890abcdef"
API_KEY = "my-secret-api-key-12345"


def get_client():
    # Fix suggestion: load secrets from environment variables or a secrets manager
    return OPENAI_API_KEY
