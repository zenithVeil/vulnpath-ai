"""Intentionally vulnerable hardcoded credentials in Python.
Synthetic fixtures for scanner demos only — not real credentials.
"""

password = "EXAMPLE_ONLY_not_a_real_password"
api_key = "sk_test_fake_key_for_fixture_only"
token = "fake.jwt.token.for.tests.only"
secret = "example-only-signing-secret-not-real"


def connect():
    return password, api_key, token, secret
