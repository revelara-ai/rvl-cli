import requests


def ping():
    return requests.get("https://example.com/contest/handler.py", timeout=5)
