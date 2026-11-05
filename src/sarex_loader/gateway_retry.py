"""Bounded retries for metadata GET only, with pacing and safe Retry-After handling."""

import random
import time
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

from sarex_loader.api_models import ApiError, ApiErrorCode


def retry_after(value):
    if not isinstance(value, str) or len(value) > 128:
        return None
    try:
        seconds = (int(value) if value.isascii() and value.isdecimal() else
                   (parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds())
        return min(60.0, max(0.0, float(seconds)))
    except (ValueError, TypeError, OverflowError):
        return None


class GetRetrier:
    def __init__(self, *, attempts=4, interval=0.5, sleep=time.sleep, clock=time.monotonic,
                 jitter=lambda: random.uniform(0, 0.25)):  # noqa: S311 — timing only
        if not 1 <= attempts <= 6 or not 0 <= interval <= 10:
            raise ValueError('Неверные ограничения повторов GET.')
        self.attempts, self.interval = attempts, interval
        self.sleep, self.clock, self.jitter = sleep, clock, jitter
        self.last_started = None
        self.calls = []

    def fetch(self, policy, token, metadata):
        from sarex_loader.gateway_tree import fetch_gateway

        metadata['attempts'] = []
        for number in range(1, self.attempts + 1):
            delay = (0 if self.last_started is None else
                     max(0, self.interval - (self.clock() - self.last_started)))
            if delay:
                self.sleep(delay)
            # Authentication POST is outside the retry boundary.
            access = token()
            measured = {'folder_id': policy.folder_id, 'attempt': number, 'error': None}
            self.last_started = started = self.clock()
            try:
                raw = fetch_gateway(policy, access, response_metadata=measured)
                metadata.update(measured)
                return raw
            except ApiError as exc:
                measured.update(error=exc.code.value, http_status=exc.status)
                transient = exc.code in {
                    ApiErrorCode.TIMEOUT, ApiErrorCode.TRANSPORT_ERROR,
                    ApiErrorCode.RATE_LIMITED, ApiErrorCode.SERVER_ERROR}
                if not transient or number == self.attempts:
                    metadata.update(measured)
                    raise
                delay = max(min(30, 2 ** (number - 1)) + self.jitter(),
                            measured.get('retry_after_seconds') or 0)
                measured['backoff_seconds'] = delay
                self.sleep(delay)
            finally:
                measured['elapsed_seconds'] = round(self.clock() - started, 3)
                metadata['attempts'].append(measured)
                self.calls.append(measured)
