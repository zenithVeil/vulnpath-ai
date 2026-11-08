"""Negative example: parameterized SQL with user input passed as bound arguments.

Same pattern as sqli_interpolated_input.py but the user input is passed as a
bound parameter to cursor.execute, never interpolated into the SQL string.
This separates "syntax present" (a SELECT against users) from
"untrusted input reaches sink" (input bound as a parameter).
"""

import sqlite3


def fetch_user(username):
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    # SAFE: username is bound as a parameter, not interpolated into the SQL.
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
