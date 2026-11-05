"""Offline Gateway response projection. No endpoints, transport, logging or file access."""

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Generic, TypeVar

from sarex_loader.api_models import ApiError, ApiErrorCode, JSONValue, decode_payload, valid_id
from sarex_loader.name_check import validate_name
from sarex_loader.safety import ValidationError

MAX_GATEWAY_BYTES = 1024**2  # Backward-compatible default, not the configurable ceiling.
HARD_MAX_GATEWAY_BYTES = 8 * 1024**2
MAX_PATH_IDS = 128
MAX_GATEWAY_NODES = 200_000  # Real 556-object export includes ~139k metadata nodes.


@dataclass(frozen=True, repr=False)
class GatewayDocument:
    id: int
    # Root-to-self chain, including this document, as observed in Gateway responses.
    path_ids: tuple[int, ...]


@dataclass(frozen=True, repr=False)
class GatewaySearchDocument:
    """Opt-in private metadata for future local PDF search; names are inert text."""

    id: int
    name: str
    is_folder: bool
    path_ids: tuple[int, ...]


DocumentT = TypeVar('DocumentT', GatewayDocument, GatewaySearchDocument)


@dataclass(frozen=True, repr=False)
class GatewayDescendants(Generic[DocumentT]):
    direct: tuple[DocumentT, ...]
    nested: tuple[DocumentT, ...]
    # Neither an empty page nor a successful parse proves server-side completeness.
    server_completeness_verified: bool = field(default=False, init=False)


@dataclass(frozen=True, repr=False)
class GatewayDocuments(Generic[DocumentT]):
    documents: tuple[DocumentT, ...]
    server_completeness_verified: bool = field(default=False, init=False)

    def descendants_of(self, parent_id: int) -> GatewayDescendants[DocumentT]:
        if not valid_id(parent_id):
            raise ApiError(ApiErrorCode.INVALID_RESPONSE)
        direct, nested = [], []
        for document in self.documents:
            path = document.path_ids
            if document.id == parent_id:
                continue
            if len(path) > 1 and path[-2] == parent_id:
                direct.append(document)
            elif parent_id in path[:-1]:
                nested.append(document)
        return GatewayDescendants(tuple(direct), tuple(nested))


def _path(value: object) -> tuple[int, ...]:
    if type(value) is not str or not value or len(value) > MAX_PATH_IDS * 20:
        raise ApiError(ApiErrorCode.INVALID_RESPONSE)
    parts = value.split('.')
    if len(parts) > MAX_PATH_IDS:
        raise ApiError(ApiErrorCode.INVALID_RESPONSE)
    ids = []
    for part in parts:
        # No whitespace stripping, Unicode digit folding, leading zero removal or URL decoding.
        if not re.fullmatch(r'[1-9][0-9]{0,18}', part):
            raise ApiError(ApiErrorCode.INVALID_RESPONSE)
        identifier = int(part)
        if not valid_id(identifier):
            raise ApiError(ApiErrorCode.INVALID_RESPONSE)
        ids.append(identifier)
    if len(ids) != len(set(ids)):
        raise ApiError(ApiErrorCode.INVALID_RESPONSE)
    return tuple(ids)


def parse_gateway_documents(
    body: bytes, *, max_response_bytes: int = MAX_GATEWAY_BYTES,
) -> GatewayDocuments[GatewayDocument]:
    """Observed envelope: {documents: [{id: int, path: str}, ...]}.

    Path must include the document itself; no alternative conventions are guessed.
    Unrecognized fields are bounded by decode_payload and discarded, never retained.
    """
    return _parse(body, max_response_bytes, _minimal_document)


def parse_gateway_search_documents(
    body: bytes, *, max_response_bytes: int = MAX_GATEWAY_BYTES,
) -> GatewayDocuments[GatewaySearchDocument]:
    """Explicitly retain validated names/types in memory, without PDF matching or output."""
    return _parse(body, max_response_bytes, _search_document)


def _minimal_document(identifier: int, path: tuple[int, ...],
                      _item: dict[str, JSONValue]) -> GatewayDocument:
    return GatewayDocument(identifier, path)


def _search_document(identifier: int, path: tuple[int, ...],
                     item: dict[str, JSONValue]) -> GatewaySearchDocument:
    name_value, is_folder = item.get('name'), item.get('is_folder')
    if type(name_value) is not str or type(is_folder) is not bool:
        raise ApiError(ApiErrorCode.INVALID_RESPONSE)
    try:
        name = validate_name(name_value)
    except ValidationError:
        raise ApiError(ApiErrorCode.INVALID_RESPONSE) from None
    return GatewaySearchDocument(identifier, name, is_folder, path)


def _parse(body: bytes, max_response_bytes: int,
           project: Callable[[int, tuple[int, ...], dict[str, JSONValue]], DocumentT],
           ) -> GatewayDocuments[DocumentT]:
    if (type(max_response_bytes) is not int
            or not 1 <= max_response_bytes <= HARD_MAX_GATEWAY_BYTES):
        raise ValidationError('Лимит ответа Gateway должен быть целым числом от 1 до 8388608.')
    if type(body) is not bytes:
        raise ApiError(ApiErrorCode.INVALID_RESPONSE)
    if len(body) > max_response_bytes:
        raise ApiError(ApiErrorCode.RESPONSE_TOO_LARGE)
    value = decode_payload(body, max_nodes=MAX_GATEWAY_NODES)
    if not isinstance(value, dict) or not isinstance(value.get('documents'), list):
        raise ApiError(ApiErrorCode.INVALID_RESPONSE)
    documents = []
    seen = set()
    parent_by_id: dict[int, int | None] = {}
    for item in value['documents']:
        if not isinstance(item, dict) or not valid_id(item.get('id')):
            raise ApiError(ApiErrorCode.INVALID_RESPONSE)
        identifier = item['id']
        if identifier in seen:
            # Even byte-identical duplicates are rejected rather than silently collapsed.
            raise ApiError(ApiErrorCode.INVALID_RESPONSE)
        seen.add(identifier)
        path = _path(item.get('path'))
        if path[-1] != identifier:
            raise ApiError(ApiErrorCode.INVALID_RESPONSE)
        # One ID cannot have different parents, including when only seen as an ancestor.
        # This also rejects inconsistent/cyclic chains across separate rows, in O(total IDs).
        previous = None
        for node in path:
            if node in parent_by_id and parent_by_id[node] != previous:
                raise ApiError(ApiErrorCode.INVALID_RESPONSE)
            parent_by_id[node] = previous
            previous = node
        documents.append(project(identifier, path, item))
    # IDs are unique; numeric ordering is independent of response order and private names.
    return GatewayDocuments(tuple(sorted(documents, key=lambda document: document.id)))
