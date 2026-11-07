"""Intentionally vulnerable SQL injection via interpolated user input.

Builds SQL with f-string / % formatting using user input, so untrusted input
reaches the sink directly. Contrasts with parameterized_sql_vs_input.py where
the same input is passed as a bound parameter instead.
"""

import sqlite3


def lookup_user(user_input):
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    # VULNERABLE: user input interpolated directly into the SQL string.
    cursor.execute(f"SELECT * FROM users WHERE username = '{user_input}'")
    rows = cursor.fetchall()
    connection.close()
    return rows


def search_orders(customer_name):
    connection = sqlite3.connect("orders.db")
    cursor = connection.cursor()
    # VULNERABLE: user input formatted into the SQL string with %.
    cursor.execute("SELECT * FROM orders WHERE customer = '%s'" % customer_name)
    rows = cursor.fetchall()
    connection.close()
    return rows
