"""Intentionally vulnerable Flask path traversal sample.

Do not use this pattern in production. It is provided so VulnPath AI can
identify unsafe file path construction from user-controlled input.
"""

from flask import Flask, request, send_file

app = Flask(__name__)


@app.route("/download")
def download():
    filename = request.args.get("file", "readme.txt")

    # VULNERABLE: user-controlled input is concatenated into a filesystem path.
    return send_file(open("/var/www/downloads/" + filename, "rb"))


if __name__ == "__main__":
    app.run(debug=True)
