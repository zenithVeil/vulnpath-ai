# Safe: allowlisted hosts only
import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.openai.com", "api.anthropic.com"}


def fetch_allowed(url):
    # GOOD: only allowlisted hosts are fetched; constant URL after check
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")
    return requests.get("https://api.openai.com/v1/models").text
