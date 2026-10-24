# Vulnerable: requests.get / urllib on user-controlled URL (SSRF)
import requests
from urllib.request import urlopen


def fetch_user_url(user_url):
    # BAD: fetching a URL supplied by the user/tool without validation
    return requests.get(user_url).text
    # Fix suggestion: validate the URL against an allowlist of hosts before fetching
