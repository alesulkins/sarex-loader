"""In-memory Gateway simulation only. The synthetic URL is NOT a Sarex endpoint."""

from collections.abc import Mapping

from sarex_loader.api_models import ApiError, ApiErrorCode
from sarex_loader.api_transport import BearerToken, GetRequest

MOCK_GATEWAY_URL = 'https://gateway.example.invalid/synthetic-documents'


class GatewayMockResponse:
    def __init__(self, body: bytes, *, status: int = 200,
                 headers: Mapping[str, str] | None = None,
                 read_error: Exception | None = None):
        if type(body) is not bytes:
            raise ApiError(ApiErrorCode.INVALID_RESPONSE)
        self._body = body
        self.status = status
        self.headers = headers if headers is not None else {
            'Content-Type': 'application/json', 'Content-Length': str(len(body)),
        }
        self._offset = 0
        self._read_error = read_error
        self.closed = False

    def read(self, max_bytes: int, *, timeout: float) -> bytes:
        if self.closed or timeout <= 0:
            raise ApiError(ApiErrorCode.TRANSPORT_ERROR)
        if self._read_error is not None:
            raise self._read_error
        chunk = self._body[self._offset:self._offset + max_bytes]
        self._offset += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = True
        self._body = b''
        self._read_error = None


class GatewayMockTransport:
    network_enabled = False

    def __init__(self, response: GatewayMockResponse, *, open_error: Exception | None = None):
        if type(response) is not GatewayMockResponse:
            raise ApiError(ApiErrorCode.NETWORK_DISABLED)
        self.response = response
        self._open_error = open_error
        self.requests: list[GetRequest] = []

    def open(self, request: GetRequest) -> GatewayMockResponse:
        # No write method is accepted even via a direct call, before response consumption.
        if type(request) is not GetRequest or request.method != 'GET':
            raise ApiError(ApiErrorCode.WRITES_DISABLED)
        if (request.url != MOCK_GATEWAY_URL or request.follow_redirects is not False
                or request.retries != 0 or request.trust_environment is not False):
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        headers = request.headers
        if (headers.keys() != {'Accept', 'Accept-Encoding', 'Authorization', 'Identity'}
                or headers['Accept'] != 'application/json'
                or headers['Accept-Encoding'] != 'identity'):
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        for key in ('Authorization', 'Identity'):
            value = headers[key]
            if type(value) is not str or not value.startswith('Bearer '):
                raise ApiError(ApiErrorCode.AUTHENTICATION)
            BearerToken(value[7:])
        if self.requests:
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        self.requests.append(request)
        if self._open_error is not None:
            raise self._open_error
        return self.response
