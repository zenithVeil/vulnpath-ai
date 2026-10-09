"""Example file with intentional security weaknesses for demonstration."""

import os
import sqlite3

# CWE-798: Hardcoded Sensitive Credential
API_KEY = "AKIAIOSFODNN7EXAMPLE_SECRET_KEY"
SECRET_KEY = "super_secret_production_key_12345"


def fetch_user_record(username: str):
    """Fetch user using insecure raw SQL string formatting."""
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # CWE-89: SQL Injection
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchall()


def read_uploaded_file(filename: str):
    """Read file using insecure unvalidated path."""
    # CWE-22: Path Traversal
    with open(f"/var/data/uploads/{filename}", "r") as file_handle:
        return file_handle.read()


def ping_host(host_ip: str):
    """Execute ping with unvalidated system command."""
    # CWE-78: Command Injection
    os.system(f"ping -c 1 {host_ip}")
