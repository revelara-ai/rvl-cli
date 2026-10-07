"""pyindex fixture for the local shapes of the misuse lane: the delay of a
retry, a query on a relation of a loop variable, SQL text built in a query
call, print-style output, and a latency metric that is not a histogram. Each
shape stands beside the neighbors that must not be emitted."""
import asyncio
import random
import sys
import time

from prometheus_client import Counter, Gauge, Histogram
from sqlalchemy import text
from tenacity import (retry, stop_after_attempt, wait_exponential, wait_fixed,
                      wait_random_exponential)


def call():
    return 1


def backoff_for(attempt):
    return 2 ** attempt


# --- retry_shape (B1/B2) ------------------------------------------------------

def retry_constant():
    for attempt in range(5):
        try:
            return call()
        except ConnectionError:
            time.sleep(2)


def retry_forever():
    # A constant delay and no limit on attempts: two shapes.
    while True:
        try:
            return call()
        except ConnectionError:
            pass
        time.sleep(1)


def retry_exponential():
    delay = 0.1
    for attempt in range(5):
        try:
            return call()
        except ConnectionError:
            time.sleep(delay)
            delay *= 2


def retry_power(max_attempts):
    # A counter in the body limits the attempts.
    attempt = 0
    while True:
        try:
            return call()
        except TimeoutError:
            attempt += 1
            if attempt >= max_attempts:
                raise
            time.sleep(2 ** attempt)


async def retry_jittered():
    for attempt in range(5):
        try:
            return call()
        except ConnectionError:
            await asyncio.sleep(2 ** attempt + random.random())


def retry_opaque():
    # A function computes the delay: its shape is not in this expression.
    for attempt in range(5):
        try:
            return call()
        except ConnectionError:
            time.sleep(backoff_for(attempt))


def ping_all(hosts):
    # A loop over items gives each item one attempt: not a retry.
    for host in hosts:
        try:
            call()
        except ConnectionError:
            time.sleep(1)


def poll():
    # A sleep between rounds of work is not on the failure path.
    while True:
        call()
        time.sleep(60)


@retry
def tenacity_bare():
    return call()


@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def tenacity_fixed():
    return call()


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
def tenacity_exponential():
    return call()


@retry(stop=stop_after_attempt(3),
       wait=wait_random_exponential(multiplier=1, max=10))
def tenacity_jittered():
    return call()


# --- loop_variable_query (N1, same function only) -----------------------------

def list_orders(customers):
    out = []
    for c in customers:
        out.append(c.orders.all())
        out.append(c.orders.filter(open=True).first())
    return out


def comprehension(customers):
    return [c.orders.all() for c in customers]


def mapped(customers):
    return list(map(lambda c: c.profile.first(), customers))


def not_a_loop_variable_query(customers, session):
    for c in customers:
        session.items.all()   # the receiver is not the loop variable
        c.all()               # no relation between the variable and the call
        c.name.count("a")     # not a query method
    return customers.orders.all()  # not in a loop


# --- sql_concat_in_call (Q4, same expression only) ----------------------------

def find_user(cur, name):
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    cur.execute("SELECT * FROM users WHERE name = '{}'".format(name))


def find_user_text(session, name):
    return session.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))


def safe_queries(cur, name):
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))
    cur.execute("SELECT * " "FROM users")
    cur.execute("SELECT * FROM " + "users")
    cur.execute(f"SELECT 1")
    # Text that another statement built is the cross-statement form.
    q = "SELECT 1 WHERE x = " + name
    cur.execute(q)


# --- print_logging (I1) -------------------------------------------------------

def report(n):
    print("processed", n)
    print("warn", n, file=sys.stderr)


def write_out(n, fh):
    print(n, file=fh)
    fh.write(str(n))


# --- latency_scalar_metric (J7) -----------------------------------------------

REQUEST_LATENCY = Gauge("http_request_latency_seconds", "mean latency")
DURATION_SUM = Counter("job_duration_seconds_total", "sum of durations")
QUEUE_DEPTH = Gauge("queue_depth", "items in the queue")
LATENCY_HIST = Histogram("http_request_duration_seconds", "latency")
