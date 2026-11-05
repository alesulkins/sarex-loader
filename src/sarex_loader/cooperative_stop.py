"""Ctrl+C requests a safe boundary; it must never raise inside a write phase."""

import signal
from contextlib import contextmanager


@contextmanager
def stop_after_file():
    requested = False

    def request_stop(_signum, _frame):
        nonlocal requested
        requested = True

    def should_stop():
        return requested

    previous = signal.signal(signal.SIGINT, request_stop)
    try:
        yield should_stop
    finally:
        signal.signal(signal.SIGINT, previous)
