"""Constructions that take a bound: queues, pools and caches.

The retriever reports each constructor's arguments. It never says which one
is a bound; a construction-bound spec does.
"""
import asyncio
import collections
import functools
import queue
from collections import deque
from functools import lru_cache

import redis

MAX_JOBS = 100


def unbounded_queue():
    return queue.Queue()


def zero_is_no_limit():
    return queue.Queue(maxsize=0)


def literal_capacity():
    return queue.Queue(50)


def constant_capacity():
    return asyncio.Queue(maxsize=MAX_JOBS)


def named_capacity(settings):
    return queue.Queue(maxsize=settings.max_jobs)


def hidden_options(opts):
    return queue.Queue(**opts)


def history():
    return deque()


def bounded_history():
    return collections.deque([], maxlen=10)


def pool(url, settings):
    unlimited = redis.ConnectionPool.from_url(url)
    limited = redis.ConnectionPool(max_connections=settings.pool_size)
    bare = redis.ConnectionPool()
    return unlimited, limited, bare


@lru_cache
def default_cache(key):
    return key


@lru_cache(maxsize=None)
def cache_forever(key):
    return key


@functools.cache
def always_unbounded(key):
    return key


def not_a_construction(q):
    # A local name that only looks like the stdlib class is not resolved.
    return Queue()
