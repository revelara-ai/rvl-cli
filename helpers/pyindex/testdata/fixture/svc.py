"""A small but realistic service module for exercising pyindex.

It mixes resolvable external-client calls (requests, redis, a db cursor) with
non-client noise that must NOT be indexed as call sites.
"""

import os
import requests
from redis import Redis


# Module-scope construction: the client and its timeout are set here, away from
# the call sites that use them.
session = requests.Session()
cache = Redis(host="localhost", port=6379, socket_timeout=2)


def fetch_user(user_id):
    """Bounded HTTP call: the timeout= is on the call itself, visible in snippet."""
    url = os.path.join("https://api.example.com/users", str(user_id))  # noise: os.path.join
    resp = requests.get(url, timeout=5)
    return resp


def refresh(session_id):
    """Unbounded HTTP call on a session constructed elsewhere (construction visible)."""
    items = []
    items.append(session_id)  # noise: list.append
    return session.get("https://api.example.com/refresh/" + session_id)


def cached_lookup(key):
    """Redis client constructed at module scope, resolves to redis.Redis."""
    return cache.get(key)


class Repo:
    def __init__(self, conn):
        self.conn = conn
        self.http = requests.Session()

    def find(self, sql):
        # db cursor call: execute is a strong I/O verb, emitted even though the
        # cursor's type cannot be resolved from a dynamic `conn`.
        cur = self.conn.cursor()
        cur.execute(sql)
        return cur.fetchall()

    def ping(self):
        # receiver self.http resolves via the __init__ construction above.
        return self.http.get("https://api.example.com/ping")


# Module-scope client call.
health = requests.get("https://api.example.com/health", timeout=3)
