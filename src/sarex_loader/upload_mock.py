"""Deterministic offline server fixture for the upload command; NEVER a Sarex adapter.

IDs, folders, dates and links are synthetic. Responses are stateless to allow a fresh
process to resume from SQLite without persisting a second simulated server database.
"""

import hashlib
import json
from dataclasses import dataclass

from sarex_loader.api_models import ApiError, ApiErrorCode
from sarex_loader.api_transport import GetRequest, JsonBody, PostRequest
from sarex_loader.api_upload_models import BundleDraft
from sarex_loader.gateway_mock_transport import GatewayMockResponse
from sarex_loader.journal import fingerprint
from sarex_loader.multipart import MultipartPDF

MOCK_ORIGIN = 'https://upload.example.invalid'
MOCK_API = MOCK_ORIGIN + '/documentations/api'
MOCK_DISK = 'synthetic-upload-disk'
MOCK_DATE = '2000-01-01T00:00:00+00:00'  # Fixture value, NOT an interpretation of Excel date.


@dataclass(frozen=True, repr=False)
class MockTarget:
    parent_id: int
    document_id: int
    bundle_id: str
    draft: BundleDraft
    pdf_sha256: str

    @property
    def url(self) -> str:
        return f'{MOCK_ORIGIN}/documentations/{self.document_id}'


class UploadMockTransport:
    network_enabled = False

    def __init__(self, operations: dict[str, dict]):
        self.targets: dict[str, MockTarget] = {}
        self._bundles = {}
        self._documents = {}
        self._filenames = {}
        # Only method/path/byte counts, never headers, names, payloads or PDF bytes.
        self.calls: list[tuple[str, str]] = []
        self.pdf_bytes = 0
        self.max_chunk_bytes = 0
        for key, item in operations.items():
            if item['status'] != 'LOCAL_MATCH':
                continue
            path = item['proposed_path']
            parent = fingerprint({'root': path['root_id'], 'parts': path['components'][:-1]})
            target = MockTarget(
                item.get('resolved_folder_id') or int(parent[:15], 16) + 1,
                int(key[:15], 16) + 1, 'mock-' + key,
                BundleDraft(MOCK_DISK, 'pdf', 'pdf', item['filename'], MOCK_DATE),
                item['pdf_sha256'],
            )
            if (target.document_id in self._documents
                    or target.draft.filename in self._filenames):
                raise ApiError(ApiErrorCode.INVALID_RESPONSE)
            self.targets[key] = target
            self._bundles[target.bundle_id] = target
            self._documents[target.document_id] = target
            self._filenames[target.draft.filename] = target

    def open(self, request: GetRequest) -> GatewayMockResponse:
        if (type(request) not in {GetRequest, PostRequest}
                or request.method not in {'GET', 'POST'}
                or not request.url.startswith(MOCK_API + '/')
                or request.follow_redirects or request.retries or request.trust_environment):
            raise ApiError(ApiErrorCode.WRITES_DISABLED)
        route = request.url[len(MOCK_API):]
        self.calls.append((request.method, route))
        result = self._respond(request, route)
        return GatewayMockResponse(json.dumps(result).encode())

    def _respond(self, request, route):
        if request.method == 'GET':
            if route == '/v1/documents/types':
                return [{'name': 'pdf', 'fields': [
                    {'key': 'pdf', 'file': True, 'can_be_uploaded_by_user': True}]}]
            if route.startswith('/v1/documents/'):
                suffix = route.removeprefix('/v1/documents/')
                if suffix.isascii() and suffix.isdecimal() and int(suffix) in self._documents:
                    return self._document(self._documents[int(suffix)])
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        if route in {'/v1/bundles', '/v1/documents'}:
            if type(request.body) is not JsonBody:
                raise ApiError(ApiErrorCode.INVALID_RESPONSE)
            value = json.loads(b''.join(request.body.iter_chunks()))  # JsonBody <=32 KiB.
            if route == '/v1/bundles':
                name = value.get('keys', [{}])[0].get('name')
                target = self._filenames.get(name)
                if target is not None and value == target.draft.payload():
                    return {'id': target.bundle_id, 'upload_status': 'created'}
            else:
                target = self._bundles.get(value.get('bundle_id'))
                if target is not None and value == {
                    'disk_id': MOCK_DISK, 'parent_id': target.parent_id,
                    'name': target.draft.filename, 'is_folder': False,
                    'bundle_id': target.bundle_id,
                }:
                    return self._document(target)
            raise ApiError(ApiErrorCode.INVALID_RESPONSE)
        parts = route.split('/')
        if len(parts) in {5, 6} and parts[1:3] == ['v1', 'bundles']:
            target = self._bundles.get(parts[3])
            if target is not None:
                if parts[4:] == ['upload_finish'] and request.body is None:
                    return {'id': target.bundle_id, 'upload_status': 'uploaded'}
                if parts[4:] == ['pdf', 'upload_single'] and type(request.body) is MultipartPDF:
                    body = request.body
                    if body.sha256 != target.pdf_sha256 or body.filename != target.draft.filename:
                        raise ApiError(ApiErrorCode.INVALID_SOURCE)
                    digest = hashlib.sha256()
                    # MultipartPDF emits one prefix, PDF chunks, one suffix. Hold at most
                    # two chunks; independently verify the PDF bytes sent through the encoder.
                    chunks = iter(body.iter_chunks())
                    prefix = next(chunks)
                    if b'name="file";' not in prefix or b'application/pdf' not in prefix:
                        raise ApiError(ApiErrorCode.INVALID_RESPONSE)
                    pending = next(chunks)
                    size = len(prefix) + len(pending)
                    for chunk in chunks:
                        digest.update(pending)
                        self.pdf_bytes += len(pending)
                        self.max_chunk_bytes = max(self.max_chunk_bytes, len(pending))
                        pending = chunk
                        size += len(chunk)
                    if (digest.hexdigest() != target.pdf_sha256 or size != body.content_length
                            or not body.complete or not pending.endswith(b'--\r\n')):
                        raise ApiError(ApiErrorCode.INVALID_SOURCE)
                    return None
        raise ApiError(ApiErrorCode.WRITES_DISABLED)

    @staticmethod
    def _document(target):
        return {'id': target.document_id, 'name': target.draft.filename,
                'is_folder': False, 'disk_id': MOCK_DISK}
