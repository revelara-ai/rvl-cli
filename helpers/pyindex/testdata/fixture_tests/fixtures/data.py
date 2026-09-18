import requests


def ping():
    return requests.get("https://example.com/fixtures/data.py", timeout=5)
