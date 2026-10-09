"""Intentionally vulnerable path traversal via f-string open()."""


def read_upload(filename):
    # VULNERABLE: user-controlled value interpolated into a filesystem path.
    with open(f"/var/data/uploads/{filename}", "r") as handle:
        return handle.read()
