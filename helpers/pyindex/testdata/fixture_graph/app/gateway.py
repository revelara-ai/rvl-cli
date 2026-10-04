"""Leaf layer: the functions that hold the I/O call sites."""

import requests


def fetch_profile(uid):
    return requests.get("https://api.example.com/users/" + str(uid), timeout=5)


def _token():
    return "t"


def _headers(token):
    return {"Authorization": token}


def fetch_with_auth(uid):
    token = _token()
    return requests.get("https://api.example.com/me", headers=_headers(token))


class Gateway:
    def __init__(self):
        self.http = requests.Session()

    def pull(self, uid):
        return self.http.get("https://api.example.com/pull/" + str(uid))
