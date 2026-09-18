import requests


def ping():
    return requests.get("https://example.com/conftest.py", timeout=5)
