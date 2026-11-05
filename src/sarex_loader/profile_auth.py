"""Explicit, locally configured login; only token issuance may use POST."""

import time
from contextlib import contextmanager
from contextvars import ContextVar

from sarex_loader.api_client import ApiSettings
from sarex_loader.auth import AuthSession
from sarex_loader.gateway_diagnostic_policy import GatewayLoginPolicy
from sarex_loader.https_transport import ReadOnlyHTTPSTransport

active_login = ContextVar('sarex_profile_login', default=None)


@contextmanager
def configured_login(settings, *, clock=time.monotonic):
    """Renew by a new normal login BEFORE expiry, never replay a failed GET or POST.

    AuthSession's existing 300-second estimate is retained. No JWT introspection,
    refresh endpoint, disk token cache, or resource client is introduced.
    """
    auth = None
    issued = 0
    metrics = {'auth_posts': 0, 'renewals': 0}

    def token():
        nonlocal auth, issued
        if auth is None or clock() - issued >= 240:
            renewed = auth is not None
            if auth is not None:
                auth.logout()
            auth = AuthSession(
                ApiSettings('https://lk.sarex.io/api', ('https://lk.sarex.io',)),
                transport=ReadOnlyHTTPSTransport(GatewayLoginPolicy(), confirmed=True),
                read_only_network_enabled=True)
            issued = clock()
            metrics['auth_posts'] += 1
            metrics['renewals'] += renewed
            auth.login(settings.username, settings.password)
        return auth.access_token(allow_refresh=False)

    token.metrics = metrics
    try:
        token()
        yield token
    finally:
        if auth is not None:
            auth.logout()


@contextmanager
def use_settings(settings):
    marker = active_login.set(lambda: configured_login(settings))
    try:
        yield
    finally:
        active_login.reset(marker)
