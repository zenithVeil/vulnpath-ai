"""Negative example: constant shell command with a fixed argument list.

No user or tool input reaches the shell; the command and its arguments are
entirely constant literals.
"""

import subprocess


def list_root_directory():
    # SAFE: constant command list, no shell interpolation, no user input.
    subprocess.run(["ls", "-la", "/"], check=True)


def ping_localhost():
    # SAFE: constant argument list, shell=False by default.
    subprocess.run(["ping", "-c", "1", "127.0.0.1"], check=True)


def get_os_name():
    # SAFE: constant command list, no variable input.
    subprocess.run(["uname", "-a"], check=False)
