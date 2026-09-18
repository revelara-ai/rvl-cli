import requests


def ping():
    return requests.get("https://example.com/svc/attestation.py", timeout=5)
