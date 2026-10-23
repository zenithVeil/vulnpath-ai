# Safe: subprocess with list args, no shell=True, fixed binary
import subprocess


def run_ls(path):
    # GOOD: argument list, no shell, fixed binary
    return subprocess.run(["ls", path], capture_output=True, text=True)
