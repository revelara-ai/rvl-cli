"""Entry module: the top of the multi-hop chains the graph tests walk.

    main -> run_once -> sync_user        -> fetch_profile   (requests.get)
                     -> Syncer.sync_all  -> Syncer._one -> Gateway.pull
"""

from app.service import Syncer, sync_user


def main():
    """Run one sync pass and exit."""
    return run_once()


def run_once():
    sync_user(7)
    return Syncer().sync_all()


if __name__ == "__main__":
    main()
