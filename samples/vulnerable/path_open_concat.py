"""Intentionally vulnerable path traversal via open() concatenation."""


def read_download(filename):
    # VULNERABLE: user-controlled path concatenated into open().
    with open("/var/www/downloads/" + filename, "r") as handle:
        return handle.read()
