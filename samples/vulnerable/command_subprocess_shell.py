"""Intentionally vulnerable command injection via subprocess and shell=True."""

import subprocess


def lookup_host(hostname):
    # VULNERABLE: concatenated command string executed through the shell.
    subprocess.run("nslookup " + hostname, shell=True)
    subprocess.Popen("traceroute " + hostname, shell=True)
    return "submitted"
