"""Trusted offline transport boundary. No socket adapter or HTTP dependency in stage 4."""

import json
import re
import ssl
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Literal, Protocol

from sarex_loader.api_models import ApiError, ApiErrorCode
from sarex_loader.safety import ValidationError


@dataclass(frozen=True, repr=False)
class BearerToken:
    """Caller-supplied token only; no environment, file, refresh or login discovery."""

    _value: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self._value, str) or len(self._value) > 4096 or not re.fullmatch(
            r'[A-Za-z0-9._~+/-]{1,4096}=*', self._value
        ):
            raise ValidationError('Некорректный формат Bearer token; значение скрыто.')

    def header_value(self) -> str:
        return 'Bearer ' + self._value


@dataclass(frozen=True, repr=False)
class GetRequest:
    url: str
    headers: Mapping[str, str]
    tls_context: ssl.SSLContext
    connect_timeout: float
    read_timeout: float
    deadline: float
    method: Literal['GET'] = field(default='GET', init=False)
    follow_redirects: Literal[False] = field(default=False, init=False)
    retries: Literal[0] = field(default=0, init=False)
    trust_environment: Literal[False] = field(default=False, init=False)


class RequestBody(Protocol):
    content_type: str
    content_length: int
    complete: bool

    def iter_chunks(self) -> Iterator[bytes]: ...


class JsonBody:
    """Opaque single-use bytes; may contain credentials, never repr or persist the payload."""

    content_type = 'application/json'

    def __init__(self, value: dict[str, object]):
        self._data = json.dumps(value, ensure_ascii=True, allow_nan=False).encode('utf-8')
        if len(self._data) > 32768:
            raise ValidationError('Тело запроса превышает локальный лимит.')
        self.content_length = len(self._data)
        self.complete = False
        self._started = False

    def iter_chunks(self) -> Iterator[bytes]:
        if self._started:
            raise ApiError(ApiErrorCode.OUTCOME_UNKNOWN, outcome_unknown=True)
        self._started = True
        try:
            yield self._data
            self.complete = True
        finally:
            self._data = b''

    def clear(self) -> None:
        self._data = b''


@dataclass(frozen=True, repr=False)
class PostRequest(GetRequest):
    body: RequestBody | None
    method: Literal['POST'] = field(default='POST', init=False)


class ReadResponse(Protocol):
    status: int
    headers: Mapping[str, str]

    def read(self, max_bytes: int, *, timeout: float) -> bytes:
        """Return at most max_bytes, EOF as b'', enforce the per-read timeout."""
        ...

    def close(self) -> None: ...


class OfflineReadTransport(Protocol):
    network_enabled: Literal[False]

    def open(self, request: GetRequest | PostRequest) -> ReadResponse:
        """Trusted test adapter: no network, redirects, retries, cookies or proxy discovery.

        Must honor request connect/read/deadline settings and TLS policy. A synchronous
        client cannot forcibly interrupt an adapter that ignores its timeout contract.
        """
        ...


class DisabledTransport:
    network_enabled: Literal[False] = False

    def open(self, request: GetRequest | PostRequest) -> ReadResponse:
        raise ApiError(ApiErrorCode.NETWORK_DISABLED)
