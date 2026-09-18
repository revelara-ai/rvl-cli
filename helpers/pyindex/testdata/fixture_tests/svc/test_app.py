import requests


def ping():
    return requests.get("https://example.com/svc/test_app.py", timeout=5)
