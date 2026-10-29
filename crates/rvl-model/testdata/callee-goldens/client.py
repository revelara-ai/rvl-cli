import json

import requests


class QueueClient:
    def __init__(self, url):
        self.url = url

    def publish(self, body):
        out = self._call_once(json.dumps(body))
        return out

    def _call_once(self, payload):
        resp = requests.post(self.url, data=payload, timeout=5)
        resp.raise_for_status()
        return resp.json()


def parse(raw):
    return json.loads(raw)


def fetch(url):
    return requests.get(url, timeout=3).text


def load(url):
    result = parse(fetch(url))
    if len(result):
        return result
    return fetch(url)


async def drain(queue):
    while queue:
        await queue.get()


def tail(n):
    # Defined near the end of the file: the block runs to the last line.
    return drain(n)
