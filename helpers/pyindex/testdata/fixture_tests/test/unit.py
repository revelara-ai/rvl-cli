import requests


def ping():
    return requests.get("https://example.com/test/unit.py", timeout=5)
