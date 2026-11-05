"""Explicit token issuance/refresh, no credential discovery or token persistence."""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

from sarex_loader.api_client import ApiSettings, SarexClient
from sarex_loader.api_models import ApiError, ApiErrorCode, JSONValue
from sarex_loader.api_transport import BearerToken, JsonBody, OfflineReadTransport
from sarex_loader.safety import ValidationError

if TYPE_CHECKING:
    from sarex_loader.https_transport import ReadOnlyHTTPSTransport


class AuthSession:
    # Lifetimes supplied by the user; not inferred from unverified JWT claims.
    ACCESS_SECONDS = 300
    REFRESH_SECONDS = 86400
    SKEW_SECONDS = 5

    def __init__(self, settings: ApiSettings, *,
                 transport: OfflineReadTransport | ReadOnlyHTTPSTransport | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 read_only_network_enabled: bool = False,
                 diagnostics_enabled: bool = False):
        self._client = SarexClient(settings, transport=transport, mock_writes_enabled=True,
                                   read_only_network_enabled=read_only_network_enabled,
                                   diagnostics_enabled=diagnostics_enabled)
        self._lock = threading.RLock()
        self._clock = clock
        self._access: BearerToken | None = None
        self._refresh: BearerToken | None = None
        self._access_until = self._refresh_until = 0.0

    @property
    def response_diagnostic(self) -> dict:
        return self._client.response_diagnostic

    def logout(self) -> None:
        with self._lock:
            self._access = self._refresh = None
            self._access_until = self._refresh_until = 0.0

    @staticmethod
    def _token(value: object) -> BearerToken:
        try:
            return BearerToken(value)
        except ValidationError:
            raise ApiError(ApiErrorCode.INVALID_RESPONSE, outcome_unknown=True) from None

    def login(self, username: str, password: str) -> None:
        with self._lock:
            self._login(username, password)

    def _request_login_response(self, username: str, password: str) -> JSONValue:
        if any(not isinstance(v, str) or not v or len(v) > 4096 for v in (username, password)):
            raise ValidationError('Нужны явно переданные непустые учётные данные.')
        self.logout()
        return self._client._exchange('POST', '/token/',
                                      JsonBody({'username': username, 'password': password}))

    def inspect_login_fields(self, username: str, password: str) -> tuple[str, ...]:
        """Issue one login request, return top-level field names, never retain token values."""
        with self._lock:
            value = None
            try:
                value = self._request_login_response(username, password)
                if not isinstance(value, dict) or len(value) > 64:
                    raise ApiError(ApiErrorCode.INVALID_RESPONSE, outcome_unknown=True)
                if any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', key) for key in value):
                    raise ApiError(ApiErrorCode.INVALID_RESPONSE, outcome_unknown=True)
                # Keys are also untrusted: do not echo credentials or a token value as a key.
                names = {key.casefold() for key in value}
                if names.intersection((username.casefold(), password.casefold())):
                    raise ApiError(ApiErrorCode.INVALID_RESPONSE, outcome_unknown=True)
                pending = list(value.values())
                while pending:
                    item = pending.pop()
                    if isinstance(item, str) and item.casefold() in names:
                        raise ApiError(ApiErrorCode.INVALID_RESPONSE, outcome_unknown=True)
                    if isinstance(item, dict):
                        pending.extend(item.values())
                    elif isinstance(item, list):
                        pending.extend(item)
                return tuple(sorted(value))
            finally:
                if isinstance(value, dict):
                    value.clear()
                self.logout()

    def _login(self, username: str, password: str) -> None:
        started = self._clock()
        value = self._request_login_response(username, password)
        if not isinstance(value, dict) or not {'access', 'refresh'} <= value.keys():
            raise ApiError(ApiErrorCode.INVALID_RESPONSE, outcome_unknown=True)
        access, refresh = self._token(value['access']), self._token(value['refresh'])
        if self._clock() >= started + self.ACCESS_SECONDS - self.SKEW_SECONDS:
            raise ApiError(ApiErrorCode.REAUTH_REQUIRED)
        self._access, self._refresh = access, refresh
        self._access_until = started + self.ACCESS_SECONDS - self.SKEW_SECONDS
        self._refresh_until = started + self.REFRESH_SECONDS - self.SKEW_SECONDS

    def refresh(self) -> None:
        with self._lock:
            self._refresh_access()

    def _refresh_access(self) -> None:
        if self._refresh is None or self._clock() >= self._refresh_until:
            self.logout()
            raise ApiError(ApiErrorCode.REAUTH_REQUIRED)
        old_refresh, refresh_until = self._refresh, self._refresh_until
        # Invalidate before POST: unknown outcome/refresh rotation must not trigger a replay.
        self.logout()
        started = self._clock()
        value = self._client._exchange('POST', '/token/refresh/',
                                       JsonBody({'refresh': old_refresh.header_value()[7:]}))
        if not isinstance(value, dict) or 'access' not in value:
            raise ApiError(ApiErrorCode.INVALID_RESPONSE, outcome_unknown=True)
        if 'refresh' in value:
            # Rotation/reuse policy is absent from the supplied examples.
            raise ApiError(ApiErrorCode.UNSUPPORTED_OPERATION, outcome_unknown=True)
        access = self._token(value['access'])
        if (self._clock() >= refresh_until
                or self._clock() >= started + self.ACCESS_SECONDS - self.SKEW_SECONDS):
            raise ApiError(ApiErrorCode.REAUTH_REQUIRED)
        self._access, self._refresh = access, old_refresh
        self._refresh_until = refresh_until  # Refresh lifetime is never silently extended.
        self._access_until = started + self.ACCESS_SECONDS - self.SKEW_SECONDS

    def access_token(self, *, allow_refresh: bool = True) -> BearerToken:
        # Refresh expiry alone does not revoke an already issued, still valid access token.
        if type(allow_refresh) is not bool:
            raise ValidationError('Нужен boolean режим обновления access.')
        with self._lock:
            if self._access is None or self._clock() >= self._access_until:
                if not allow_refresh:
                    self.logout()
                    raise ApiError(ApiErrorCode.REAUTH_REQUIRED)
                self.refresh()
            return self._access
