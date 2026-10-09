"""Negative example: path join with basename, abspath, and prefix checks."""

import os


def read_upload(filename):
    base_dir = os.path.abspath("/var/data/uploads")
    safe_name = os.path.basename(filename)
    candidate = os.path.abspath(os.path.join(base_dir, safe_name))
    if not candidate.startswith(base_dir):
        raise ValueError("path traversal blocked")
    with open(candidate, "r", encoding="utf-8") as handle:
        return handle.read()
