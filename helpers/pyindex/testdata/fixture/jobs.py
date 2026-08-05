"""Background-job registration surfaces (G3, po-av01j.4).

Celery tasks (decorator idiom), an apscheduler cron registration, and an rq
dispatcher + worker loop. One celery task carries a time_limit (bounded), one
is bare -- the pair the job-altitude timeout judgment must tell apart. The
unresolved lookalike at the bottom must NOT be emitted: detection is
import-resolution-driven, abstain rather than guess.
"""

from celery import Celery, shared_task
from apscheduler.schedulers.background import BackgroundScheduler
from rq import Queue, Worker

app = Celery("tasks", broker="redis://localhost")
sched = BackgroundScheduler()
queue = Queue()


@app.task
def rebuild_index():
    """Bare registration: no bound of any kind on the task."""
    return "rebuilt"


@shared_task(time_limit=120)
def prune_old():
    """Bounded registration: the decorator carries the run bound."""
    return "pruned"


@sched.scheduled_job("interval", minutes=30)
def poll_upstream():
    """Cron-style registration on the scheduler object."""
    return "polled"


def enqueue_rebuild():
    """Dispatcher: hands work to the queue for a worker to run later."""
    queue.enqueue(rebuild_index)


def run_worker():
    """Worker loop: blocks consuming jobs."""
    w = Worker([queue])
    w.work()


def not_a_job(registry):
    """Lookalike: `enqueue` on an unresolved receiver is never guessed at."""
    registry.enqueue("noop")
