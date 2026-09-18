import requests


def ping():
    return requests.get("https://example.com/testing/helpers.py", timeout=5)
