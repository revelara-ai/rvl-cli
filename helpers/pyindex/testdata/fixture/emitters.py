"""G4 emission fixture: log statements, error-capture sites, and except
blocks that log, swallow, or re-raise."""

import logging
import sentry_sdk
from loguru import logger as loguru_logger

log = logging.getLogger(__name__)


def chatty(x):
    """Five logging calls -> ONE aggregate packet with count 5."""
    log.debug("a")
    log.info("b")
    log.warning("c")
    log.error("d")
    log.info("e: %s", x)


def guarded(conn):
    """An except block that LOGS: category upgrades to error_capture, and the
    handler is instrumented, never a swallow."""
    try:
        conn.execute("SELECT 1")
    except Exception:
        log.exception("query failed")


def swallowing(conn):
    """Two except blocks that emit nothing and do not re-raise: the
    except_handler swallow aggregate with count 2."""
    try:
        conn.execute("SELECT 1")
    except Exception:
        pass
    try:
        conn.execute("SELECT 2")
    except Exception:
        return None


def reraising(conn):
    """An except block that re-raises propagates the error: NOT a swallow."""
    try:
        conn.execute("SELECT 3")
    except Exception:
        raise


def captured(e):
    """A sentry capture: error_capture on the sentry_sdk identity."""
    sentry_sdk.capture_exception(e)


def loguru_user():
    loguru_logger.info("hello")
