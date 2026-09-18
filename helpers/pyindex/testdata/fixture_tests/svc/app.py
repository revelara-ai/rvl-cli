import requests


def ping():
    return requests.get("https://example.com/svc/app.py", timeout=5)
