"""Roots with structural facts, a cycle, and a recursion."""

import requests

from .gateway import fetch_profile


def retrying(fn):
    return fn


@retrying
def nightly():
    """Refresh everything once a night."""
    return refresh_all()


def refresh_all():
    return requests.post("https://api.example.com/refresh")


def register(sched):
    # `nightly` is handed over, not called: referenced_as_value on its root.
    sched.every(24, nightly)


def _warm():
    return fetch_profile(0)


def ping(n):
    return pong(n)


def pong(n):
    # ping <-> pong call each other and nothing else calls either.
    requests.head("https://api.example.com/pong")
    return ping(n - 1)


def walk(n):
    # Calls only itself: the function is its own chain root.
    requests.delete("https://api.example.com/node/" + str(n))
    return walk(n - 1)
