"""Intentionally vulnerable reflected XSS in a Python response body."""


def search_page(input):
    # VULNERABLE: untrusted input concatenated into HTML.
    return "<h1>Results for: " + input
