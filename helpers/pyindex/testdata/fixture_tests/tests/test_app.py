import requests


def ping():
    return requests.get("https://example.com/tests/test_app.py", timeout=5)
