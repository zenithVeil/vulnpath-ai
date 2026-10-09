"""Example file demonstrating defensive security remediation practices."""

import os
import sqlite3
import subprocess
from pathlib import Path

# Secure secret retrieval via environment variable
API_KEY = os.environ.get("API_KEY", "")


def fetch_user_record_secure(username: str):
    """Fetch user securely using parameterized query."""
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # Parameterized query prevents SQL injection
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchall()


def read_uploaded_file_secure(filename: str):
    """Read file with path traversal defense."""
    base_dir = Path("/var/data/uploads").resolve()
    safe_filename = Path(filename).name
    target_path = (base_dir / safe_filename).resolve()

    if not target_path.is_relative_to(base_dir):
        raise ValueError("Invalid file path: path traversal detected")

    return target_path.read_text(encoding="utf-8")


def ping_host_secure(host_ip: str):
    """Execute ping safely without shell interpolation."""
    # List of arguments prevents command injection
    subprocess.run(["ping", "-c", "1", host_ip], check=True)
