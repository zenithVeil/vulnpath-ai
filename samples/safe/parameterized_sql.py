"""Negative example: parameterized SQL queries (no string-built SQL)."""

import sqlite3


def fetch_user(user_id):
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    connection.close()
    return row


def search_orders(customer_name):
    connection = sqlite3.connect("orders.db")
    cursor = connection.cursor()
    cursor.execute(
        "SELECT * FROM orders WHERE customer = ?",
        (customer_name,),
    )
    rows = cursor.fetchall()
    connection.close()
    return rows
