"""Middle layer: one function hop and one method hop."""

from app import gateway
from app.gateway import fetch_profile


def sync_user(uid):
    return fetch_profile(uid)


class Syncer:
    def __init__(self):
        self.gw = gateway.Gateway()

    def sync_all(self):
        return self._one(1)

    def _one(self, uid):
        return self.gw.pull(uid)
