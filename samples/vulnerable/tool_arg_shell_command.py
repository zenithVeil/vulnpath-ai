"""Intentionally vulnerable command injection via tool argument.

Builds a shell command from a user/tool argument and executes it with
shell=True, so untrusted input reaches the system command sink.
"""

import subprocess


def run_tool(tool_arg):
    # VULNERABLE: tool argument interpolated into a shell command string.
    subprocess.run("echo " + tool_arg, shell=True)
    return "submitted"


def execute_command(user_input):
    # VULNERABLE: user input passed to subprocess.run with shell=True.
    subprocess.run(f"ls -la {user_input}", shell=True)
    return "done"
