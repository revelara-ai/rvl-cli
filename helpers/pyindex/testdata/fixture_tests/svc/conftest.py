import requests


def ping():
    return requests.get("https://example.com/svc/conftest.py", timeout=5)
