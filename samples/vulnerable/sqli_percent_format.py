"""Intentionally vulnerable SQL injection via percent-formatting."""

import sqlite3


def search_orders(customer_name):
    connection = sqlite3.connect("orders.db")
    cursor = connection.cursor()
    # VULNERABLE: query built with % formatting instead of bound parameters.
    cursor.execute("SELECT * FROM orders WHERE customer = '%s'" % customer_name)
    rows = cursor.fetchall()
    connection.close()
    return rows
