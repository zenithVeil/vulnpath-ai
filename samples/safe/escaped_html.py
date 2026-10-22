"""Negative example: HTML output escaped before rendering."""

import html


def search_page(user_input):
    safe = html.escape(user_input)
    return "<h1>Results for: " + safe + "</h1>"
