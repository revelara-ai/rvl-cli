import requests


def ping():
    return requests.get("https://example.com/svc/app_test.py", timeout=5)
