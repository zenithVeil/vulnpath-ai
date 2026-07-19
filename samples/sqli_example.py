"""Intentionally vulnerable Flask SQL injection sample.

Do not use this pattern in production. It is provided so VulnPath AI can
identify and explain unsafe SQL string interpolation in a small app.
"""

import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # VULNERABLE: user-controlled values are concatenated directly into SQL.
    query = (
        "SELECT id, username FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    user = cursor.execute(query).fetchone()
    connection.close()

    if user:
        return f"Welcome, {user[1]}!"

    return "Invalid username or password", 401


if __name__ == "__main__":
    app.run(debug=True)
