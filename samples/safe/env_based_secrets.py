"""Negative example: secrets loaded from the environment, not source."""

import os

password = os.environ.get("DB_PASSWORD")
api_key = os.environ.get("API_KEY")
token = os.environ.get("AUTH_TOKEN")
secret = os.getenv("APP_SECRET")
