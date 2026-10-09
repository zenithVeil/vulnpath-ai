"""Intentionally vulnerable hardcoded credentials in Python."""

password = "admin123!"
api_key = "sk_live_example_hardcoded_key"
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example"
secret = "production-signing-secret"


def connect():
    return password, api_key, token, secret
