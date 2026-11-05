"""Closed projection of untrusted response headers; no response bodies or arbitrary text."""

import re
from collections.abc import Mapping
from typing import TypedDict

from sarex_loader.api_transport import BearerToken

MEDIA_TYPES = frozenset({
    'application/json', 'application/problem+json', 'text/html', 'text/plain',
    'application/octet-stream',
})
REQUEST_ID_PATTERN = re.compile(
    r'(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
    r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12})'
)


class ResponseMetadata(TypedDict):
    content_type: str | None
    request_id: str | None
    request_id_header: str | None


def safe_response_metadata(headers: Mapping[str, str], access: BearerToken) -> ResponseMetadata:
    result: ResponseMetadata = {'content_type': None, 'request_id': None, 'request_id_header': None}
    if not isinstance(headers, Mapping) or len(headers) > 64:
        return result
    access_value = access.header_value()[7:].casefold()
    selected: dict[str, list[str]] = {}
    for key, value in headers.items():
        if type(key) is str and key.lower() in ('content-type', 'x-request-id', 'x-correlation-id'):
            selected.setdefault(key.lower(), []).append(value)

    def one(name: str, limit: int) -> str | None:
        values = selected.get(name, [])
        if len(values) != 1:
            return None
        value = values[0]
        if (type(value) is not str or len(value) > limit or not value.isascii()
                or any(ord(c) < 32 or ord(c) == 127 for c in value)):
            return None
        return value

    content_type = one('content-type', 256)
    if content_type is not None:
        # Parameters may contain secrets; return only a known media type, never raw text.
        media_type = content_type.split(';', 1)[0].strip().lower()
        if media_type in MEDIA_TYPES and media_type != access_value:
            result['content_type'] = media_type
    for header in ('x-request-id', 'x-correlation-id'):
        identifier = one(header, 36)
        if (identifier is not None and REQUEST_ID_PATTERN.fullmatch(identifier)
                and identifier.casefold() != access_value):
            result['request_id'] = identifier
            result['request_id_header'] = header
            break
    return result
