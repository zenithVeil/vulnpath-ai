"""Intentionally vulnerable SQL injection via string concatenation."""

import sqlite3


def lookup_user(user_id):
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    # VULNERABLE: user input concatenated into the SQL statement.
    cursor.execute("SELECT * FROM users WHERE id=" + user_id)
    rows = cursor.fetchall()
    connection.close()
    return rows
