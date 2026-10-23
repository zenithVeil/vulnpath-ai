# Safe: secrets from environment only
import os


def get_openai_key():
    # GOOD: read from environment, never hardcoded
    return os.environ.get("OPENAI_API_KEY")
