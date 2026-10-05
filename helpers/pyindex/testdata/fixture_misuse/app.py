"""pyindex fixture for the misuse lane: overbroad catches, blocking and
synchronous waits inside async functions, tasks nobody holds, and async calls
that are never awaited."""
import asyncio
import logging
import subprocess
import time
from time import sleep

import requests

log = logging.getLogger(__name__)


# --- overbroad_catch (H2) ---------------------------------------------------

def catches_root():
    try:
        work()
    except Exception as e:
        log.error("failed: %s", e)
    try:
        work()
    except (ValueError, Exception):
        log.error("failed again")


def catches_base():
    try:
        work()
    except BaseException:
        log.error("failed")


def catches_bare():
    try:
        work()
    except:  # noqa: E722
        log.error("failed")


def catches_and_reraises():
    try:
        work()
    except Exception:
        log.error("failed")
        raise


def catches_narrow():
    try:
        work()
    except ValueError:
        log.error("bad value")


def swallows():
    # No emission and no raise: this is the emission lane's swallow (H1).
    try:
        work()
    except Exception:
        pass


# --- blocking_in_async (G6) and sync_over_async (G5) -------------------------

async def blocks():
    time.sleep(1)
    sleep(2)
    requests.get("https://example.com")
    subprocess.run(["true"])


async def offloads(loop):
    # The blocking call is handed to a worker: not on the event loop.
    await loop.run_in_executor(None, lambda: requests.get("https://example.com"))
    await asyncio.to_thread(time.sleep, 1)

    def helper():
        time.sleep(1)

    await loop.run_in_executor(None, helper)
    await asyncio.sleep(1)


def sync_caller():
    time.sleep(1)
    asyncio.run(fetch())


async def waits_synchronously(loop, other_loop):
    asyncio.run(fetch())
    loop.run_until_complete(fetch())
    asyncio.run_coroutine_threadsafe(fetch(), other_loop).result()


# --- fire_and_forget (E5) and missing_await (E6) -----------------------------

async def fetch():
    await asyncio.sleep(0)


def work():
    return 1


async def forgets():
    asyncio.create_task(fetch())
    asyncio.ensure_future(fetch())


async def holds():
    task = asyncio.create_task(fetch())
    await task
    async with asyncio.TaskGroup() as tg:
        tg.create_task(fetch())


async def never_awaits():
    fetch()
    pending = fetch()
    work()


async def awaits():
    await fetch()
    coro = fetch()
    await coro
    return fetch()


def shadows(fetch):
    # A parameter named like the coroutine is not the coroutine.
    fetch()


class Service:
    async def refresh(self):
        await asyncio.sleep(0)

    def ping(self):
        return 1

    async def run(self):
        self.refresh()
        self.ping()
        await self.refresh()
