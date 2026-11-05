"""One approved month-folder POST, with fixed payload and durable response evidence."""

import json
import threading

from sarex_loader.api_client import Timeouts, _read_response_body, _status_error
from sarex_loader.api_models import ApiError, ApiErrorCode, decode_payload, valid_id
from sarex_loader.api_transport import BearerToken, JsonBody, PostRequest
from sarex_loader.folder_ledger import FolderLedger, operation_key, validate_plan
from sarex_loader.https_transport import ReadOnlyHTTPSTransport, checked_request_headers
from sarex_loader.read_only_policy import DOCUMENTATION_BASE, ReadOnlyPolicy


class _Replay:
    status = 200

    def __init__(self, value):
        self.body = json.dumps(value).encode()
        self.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(self.body))}

    def read(self, max_bytes, *, timeout):
        part, self.body = self.body[:max_bytes], self.body[max_bytes:]
        return part

    def close(self):
        self.body = b''


class FolderHTTPSTransport(ReadOnlyHTTPSTransport):
    """No bundles, uploads, arbitrary folders, retries, redirects or alternate hosts."""

    def __init__(self, ledger, key, plan, *, confirmed=False):
        validate_plan(plan)
        if (type(ledger) is not FolderLedger or confirmed is not True
                or operation_key(plan) != key or ledger.operation(key) != plan):
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        super().__init__(ReadOnlyPolicy((plan['parent_id'],)), confirmed=True)
        self.ledger, self.key = ledger, key
        self.plan = json.loads(json.dumps(plan))
        self.used = self.denied = False
        self._outer = threading.Lock()
        self.timeouts = Timeouts()
        self.max_requests, self.max_response_bytes = 1, 1024**2

    @property
    def policy(self):
        return self

    def authorize(self, method, url):
        self.ledger._verify_directory()
        if (method != 'POST' or url != DOCUMENTATION_BASE + '/v1/documents'
                or self.used or self.ledger.operation(self.key) != self.plan
                or self.ledger.checkpoint(self.key)['state'] != 'IN_FLIGHT'
                or self.ledger.checkpoint(self.key)['document_id'] is not None
                or any(k != self.key and c['state'] in {'IN_FLIGHT', 'OUTCOME_UNKNOWN'}
                       for k, c in self.ledger.checkpoints().items())):
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        return 'api.sarex.io', '/documentations/api/v1/documents', False

    def _validate(self, request):
        if type(request) is not PostRequest or type(request.body) is not JsonBody:
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        host, path, _ = self.authorize(request.method, request.url)
        headers = checked_request_headers(request, auth=False, has_body=True)
        token = headers['Authorization']
        if not isinstance(token, str) or not token.startswith('Bearer '):
            raise ApiError(ApiErrorCode.AUTHENTICATION)
        BearerToken(token[7:])
        if (headers.get('Content-Type') != 'application/json'
                or not 1 <= request.body.content_length <= 32768
                or headers.get('Content-Length') != str(request.body.content_length)):
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        raw = b''.join(request.body.iter_chunks())
        expected = {k: self.plan[k] for k in ('disk_id', 'parent_id', 'name')}
        value = decode_payload(raw)
        if (len(raw) != request.body.content_length
                or value != {**expected, 'is_folder': True}
                or value.get('is_folder') is not True
                or type(value.get('parent_id')) is not int):
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        self.used = True  # Consumed before DNS; even an interrupted attempt is never repeated.
        return host, path, raw, headers

    def open(self, request):
        if not self._outer.acquire(blocking=False):
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        response = None
        try:
            response = super().open(request)
            self.denied = response.status == 403
            if error := _status_error(response.status):
                raise error
            raw = _read_response_body(response, self.max_response_bytes,
                                      self.timeouts, request.deadline)
            value = decode_payload(raw)
            if isinstance(value, dict) and valid_id(value.get('id')):
                self.ledger.candidate(self.key, value['id'])
            return _Replay(value)
        finally:
            try:
                if response is not None:
                    response.close()
            finally:
                self._outer.release()
