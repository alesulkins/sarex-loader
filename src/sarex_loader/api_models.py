"""Minimal typed projection of Documentation Document, with explicit local invariants."""

import json
import math
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import TypeAlias

JSONValue: TypeAlias = str | int | float | bool | None | list['JSONValue'] | dict[str, 'JSONValue']
MAX_ID = 2**63 - 1
MAX_ITEMS = 10_000
MAX_ANCESTORS = 256
MAX_DEPTH = 32
MAX_NODES = 50_000
HARD_MAX_NODES = 200_000
MAX_STRING = 8192


class ApiErrorCode(Enum):
    NETWORK_DISABLED = 'NETWORK_DISABLED'
    AUTHENTICATION = 'AUTHENTICATION'
    ACCESS_DENIED = 'ACCESS_DENIED'
    NOT_FOUND = 'NOT_FOUND'
    RATE_LIMITED = 'RATE_LIMITED'
    SERVER_ERROR = 'SERVER_ERROR'
    HTTP_ERROR = 'HTTP_ERROR'
    REDIRECT_REJECTED = 'REDIRECT_REJECTED'
    TIMEOUT = 'TIMEOUT'
    TLS_ERROR = 'TLS_ERROR'
    TRANSPORT_ERROR = 'TRANSPORT_ERROR'
    RESPONSE_TOO_LARGE = 'RESPONSE_TOO_LARGE'
    INVALID_RESPONSE = 'INVALID_RESPONSE'
    WRITES_DISABLED = 'WRITES_DISABLED'
    REAUTH_REQUIRED = 'REAUTH_REQUIRED'
    OUTCOME_UNKNOWN = 'OUTCOME_UNKNOWN'
    UNSUPPORTED_OPERATION = 'UNSUPPORTED_OPERATION'
    INVALID_SOURCE = 'INVALID_SOURCE'


class ApiError(Exception):
    """Only a closed error code and validated HTTP status; never raw server/transport text."""

    def __init__(self, code: ApiErrorCode, status: int | None = None, *,
                 outcome_unknown: bool = False):
        if not isinstance(code, ApiErrorCode):
            raise TypeError('Expected an API error code.')
        if status is not None and (type(status) is not int or not 100 <= status <= 599):
            raise TypeError('Expected an HTTP status.')
        self.code = code
        self.status = status
        self.outcome_unknown = outcome_unknown
        super().__init__(code.value)


def valid_id(value: object) -> bool:
    return type(value) is int and 1 <= value <= MAX_ID


def _invalid() -> ApiError:
    return ApiError(ApiErrorCode.INVALID_RESPONSE)


def _object(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise _invalid()
        result[key] = value
    return result


def _integer(value: str) -> int:
    if len(value) > 20:
        raise _invalid()
    return int(value)


def _float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise _invalid()
    return result


def _constant(_value: str) -> JSONValue:
    raise _invalid()


def decode_payload(body: bytes, *, max_nodes: int = MAX_NODES) -> JSONValue:
    """Byte bound is enforced before this function; reject deep JSON before deserialization."""
    if type(max_nodes) is not int or not 1 <= max_nodes <= HARD_MAX_NODES:
        raise _invalid()
    try:
        text = body.decode('utf-8')
        depth, quoted, escaped = 0, False, False
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in '[{':
                depth += 1
                if depth > MAX_DEPTH:
                    raise _invalid()
            elif char in ']}':
                depth -= 1
                if depth < 0:
                    raise _invalid()
        result = json.loads(text, object_pairs_hook=_object, parse_int=_integer,
                            parse_float=_float, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise _invalid() from None
    pending = [result]
    count = 0
    while pending:
        value = pending.pop()
        count += 1
        if count > max_nodes:
            raise _invalid()
        if isinstance(value, (list, dict)):
            if len(value) > MAX_ITEMS:
                raise _invalid()
            pending.extend(value)
            if isinstance(value, dict):
                pending.extend(value.values())
        elif isinstance(value, str) and (
            len(value) > MAX_STRING
            or any(unicodedata.category(c).startswith('C') for c in value)
        ):
            raise _invalid()
    return result


@dataclass(frozen=True, repr=False)
class Document:
    """Not the entire Swagger model. Missing children remain None, never assumed empty.

    id/name/is_folder are a stricter *local* minimum: Swagger has no required list.
    Other remote fields are discarded; paths and workspace IDs are inert data, not URLs.
    """

    id: int
    name: str
    is_folder: bool
    disk_id: str | None = None
    path: str | None = None
    workspace_id: str | None = None
    files: tuple[int, ...] | None = None
    folders: tuple[int, ...] | None = None


def parse_document(value: JSONValue) -> Document:
    if not isinstance(value, dict) or not valid_id(value.get('id')):
        raise _invalid()
    if not isinstance(value.get('name'), str) or not value['name'].strip():
        raise _invalid()
    if type(value.get('is_folder')) is not bool:
        raise _invalid()
    strings = {}
    for key in ('disk_id', 'path', 'workspace_id'):
        if key in value and not isinstance(value[key], str):
            raise _invalid()
        strings[key] = value.get(key)
    children = {}
    for key in ('files', 'folders'):
        if key not in value:
            children[key] = None
            continue
        items = value[key]
        if not isinstance(items, list) or any(not valid_id(item) for item in items):
            raise _invalid()
        if len(items) != len(set(items)) or value['id'] in items:
            raise _invalid()
        children[key] = tuple(items)
    if set(children['files'] or ()) & set(children['folders'] or ()):
        raise _invalid()
    return Document(id=value['id'], name=value['name'], is_folder=value['is_folder'],
                    **strings, **children)


def parse_ancestors(value: JSONValue) -> tuple[Document, ...]:
    if not isinstance(value, list) or len(value) > MAX_ANCESTORS:
        raise _invalid()
    documents = tuple(parse_document(item) for item in value)
    if len({item.id for item in documents}) != len(documents):
        raise _invalid()
    return documents
