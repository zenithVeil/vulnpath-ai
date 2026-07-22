"""Intentionally vulnerable command injection sample.

Do not use these patterns in production. This file is provided so VulnPath AI
can identify unsafe shell command construction from user-controlled values.
"""

import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")

    # VULNERABLE: user-controlled input is concatenated into shell commands.
    os.system("ping -c 1 " + host)
    subprocess.run("nslookup " + host, shell=True)
    os.popen("traceroute " + host)
    eval("print('Checking ' + " + repr(host) + ")")

    return "Command submitted"


if __name__ == "__main__":
    app.run(debug=True)
