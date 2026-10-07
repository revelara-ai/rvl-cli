"""More direct callers than the caller budget, and calls that must NOT bind."""

import requests


def leaf():
    return requests.put("https://api.example.com/leaf")


def c1():
    return leaf()


def c2():
    return leaf()


def c3():
    return leaf()


def c4():
    return leaf()


def c5():
    return leaf()


def dynamic(obj):
    # An unresolved receiver: `obj.leaf` is not the module's `leaf`.
    return obj.leaf()


def shadowed(leaf):
    # The parameter shadows the module-level function: no edge.
    return leaf()


def outer():
    # The nested def's parameter is its own: it does not shadow `leaf` here.
    def inner(leaf):
        return leaf

    inner(None)
    return leaf()
