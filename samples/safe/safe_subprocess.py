"""Negative example: subprocess argument list, no shell interpolation."""

import subprocess


def ping_host(host_ip):
    subprocess.run(["ping", "-c", "1", host_ip], check=True)


def lookup_host(hostname):
    subprocess.run(["nslookup", hostname], check=False)
