# Safe: allowlisted hosts only
import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.openai.com", "api.anthropic.com"}


def fetch_allowed(url):
    # GOOD: only allowlisted hosts are fetched
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")
    return requests.get(url).text
