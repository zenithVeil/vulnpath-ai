"""Intentionally vulnerable command injection via os.popen / os.system."""

import os


def list_directory(dirname):
    # VULNERABLE: user-controlled value concatenated into a shell command.
    os.system("ls -la " + dirname)
    return os.popen("du -sh " + dirname).read()
