"""Negative example: parameterized SQL with user input passed as a bound argument.

User input reaches the query only as a bound parameter (?), never interpolated
into the SQL string. The query syntax is safe while still using untrusted input,
separating "syntax present" from "untrusted input reaches sink".
"""

import sqlite3


def fetch_user(username):
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    # SAFE: username is a bound parameter, not interpolated into the SQL string.
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    connection.close()
    return row


def search_orders(customer_name):
    connection = sqlite3.connect("orders.db")
    cursor = connection.cursor()
    cursor.execute(
        "SELECT * FROM orders WHERE customer = ? AND status = ?",
        (customer_name, "shipped"),
    )
    rows = cursor.fetchall()
    connection.close()
    return rows
