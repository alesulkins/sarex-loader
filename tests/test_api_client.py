"""Synthetic API responses only; all socket/DNS/handshake attempts fail the test."""

import json
import socket
import ssl
import traceback
from types import SimpleNamespace

import pytest

from sarex_loader.api_client import ApiSettings, SarexClient, Timeouts
from sarex_loader.api_models import MAX_ANCESTORS, ApiError, ApiErrorCode, Document
from sarex_loader.api_transport import BearerToken
from sarex_loader.safety import ValidationError

ORIGIN = 'https://api.example.invalid'


def document(identifier=7, **fields):
    return {'id': identifier, 'name': 'Synthetic document', 'is_folder': True, **fields}


class FakeResponse:
    def __init__(self, value=None, *, body=None, status=200, headers=None, read_error=None):
        self.body = body if body is not None else json.dumps(value).encode()
        self.status = status
        self.headers = headers if headers is not None else {'Content-Type': 'application/json'}
        self.read_error = read_error
        self.closed = False
        self.offset = 0
        self.reads = []

    def read(self, max_bytes, *, timeout):
        self.reads.append((max_bytes, timeout))
        if self.read_error:
            raise self.read_error
        chunk = self.body[self.offset:self.offset + min(max_bytes, 1024)]
        self.offset += len(chunk)
        return chunk

    def close(self):
        self.closed = True


class FakeTransport:
    network_enabled = False

    def __init__(self, response=None, *, error=None):
        self.response = response if response is not None else FakeResponse(document())
        self.error = error
        self.requests = []

    def open(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return self.response


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    attempts = []

    def denied(*_args, **_kwargs):
        attempts.append(True)
        raise RuntimeError('Network forbidden in API tests')

    for name in ('socket', 'getaddrinfo', 'gethostbyname', 'create_connection'):
        monkeypatch.setattr(socket, name, denied)
    monkeypatch.setattr(ssl.SSLContext, 'wrap_socket', denied)
    yield
    assert not attempts, 'A real network or TLS attempt occurred, even if caught by the client'


def client(transport=None, **settings):
    return SarexClient(ApiSettings(ORIGIN, (ORIGIN,), **settings),
                       BearerToken('synthetic-test-only'), transport=transport)


def assert_error(transport, code, **settings):
    with pytest.raises(ApiError) as caught:
        client(transport, **settings).get_document(7)
    assert caught.value.code == code
    assert len(transport.requests) == 1
    if transport.error is None:
        assert transport.response.closed
    return caught.value


def test_document_projection_and_read_request_policy():
    transport = FakeTransport(FakeResponse(document(
        disk_id='synthetic-disk', path='/remote/inert/path', workspace_id='synthetic-workspace',
        files=[8, 9], folders=[10], public_link='https://untrusted.invalid/?secret=synthetic',
    )))
    result = client(transport).get_document(7)
    assert isinstance(result, Document)
    assert result.id == 7 and result.files == (8, 9) and result.folders == (10,)
    assert result.path == '/remote/inert/path'
    assert not hasattr(result, 'public_link')
    request = transport.requests[0]
    assert request.url == ORIGIN + '/v1/documents/7'
    assert request.method == 'GET'
    assert request.headers['Authorization'] == 'Bearer synthetic-test-only'
    assert request.headers['Accept-Encoding'] == 'identity'
    assert request.tls_context.check_hostname is True
    assert request.tls_context.verify_mode == ssl.CERT_REQUIRED
    assert request.tls_context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert request.connect_timeout == 5 and request.read_timeout == 10
    assert request.follow_redirects is False and request.retries == 0
    assert request.trust_environment is False
    assert all(0 < timeout <= 10 for _, timeout in transport.response.reads)
    assert transport.response.closed
    assert 'synthetic-test-only' not in repr(request)
    assert 'Synthetic document' not in repr(result)
    with pytest.raises(TypeError):
        request.headers['Authorization'] = 'changed'


def test_missing_children_are_not_assumed_empty():
    assert client(FakeTransport()).get_document(7).files is None
    assert client(FakeTransport(FakeResponse(document(files=[])))).get_document(7).files == ()


@pytest.mark.parametrize('prefix', ['', '/api', '/gateway/api/'])
def test_prefix_is_explicit_not_inferred_from_specification(prefix):
    transport = FakeTransport()
    instance = SarexClient(ApiSettings(ORIGIN + prefix, (ORIGIN,)),
                           BearerToken('synthetic-only'), transport=transport)
    instance.get_document(7)
    assert transport.requests[0].url == ORIGIN + prefix.rstrip('/') + '/v1/documents/7'


def test_ancestors_no_recursion_no_invented_order():
    transport = FakeTransport(FakeResponse([document(10), document(2)]))
    result = client(transport).get_ancestors(7)
    assert tuple(d.id for d in result) == (10, 2)
    assert transport.requests[0].url.endswith('/v1/documents/7/ancestors')
    assert len(transport.requests) == 1 and transport.response.closed
    assert client(FakeTransport(FakeResponse([]))).get_ancestors(7) == ()


@pytest.mark.parametrize('value', [document(), [document(), document()],
                                  [document(i + 1) for i in range(MAX_ANCESTORS + 1)]])
def test_invalid_ancestor_shapes_duplicates_and_limit(value):
    transport = FakeTransport(FakeResponse(value))
    with pytest.raises(ApiError, match='INVALID_RESPONSE'):
        client(transport).get_ancestors(7)
    assert transport.response.closed and len(transport.requests) == 1


@pytest.mark.parametrize('status, code', [
    (400, ApiErrorCode.HTTP_ERROR), (401, ApiErrorCode.AUTHENTICATION),
    (403, ApiErrorCode.ACCESS_DENIED), (404, ApiErrorCode.NOT_FOUND),
    (409, ApiErrorCode.HTTP_ERROR), (429, ApiErrorCode.RATE_LIMITED),
    (500, ApiErrorCode.SERVER_ERROR), (502, ApiErrorCode.SERVER_ERROR),
    (503, ApiErrorCode.SERVER_ERROR), (204, ApiErrorCode.HTTP_ERROR),
    (301, ApiErrorCode.REDIRECT_REJECTED), (302, ApiErrorCode.REDIRECT_REJECTED),
    (307, ApiErrorCode.REDIRECT_REJECTED), (308, ApiErrorCode.REDIRECT_REJECTED),
])
def test_status_errors_do_not_read_bodies_follow_redirects_or_retry(status, code):
    transport = FakeTransport(FakeResponse(
        body=b'SYNTHETIC_SENSITIVE_SERVER_MESSAGE', status=status,
        headers={'Location': 'https://other.invalid/', 'Retry-After': '0'},
    ))
    error = assert_error(transport, code)
    assert error.status == status
    assert not transport.response.reads
    assert 'SYNTHETIC' not in str(error) + repr(error)


@pytest.mark.parametrize('value', [True, '200', None, 0, 600])
def test_invalid_status(value):
    assert_error(FakeTransport(FakeResponse(document(), status=value)),
                 ApiErrorCode.INVALID_RESPONSE)


@pytest.mark.parametrize('error, code', [
    (TimeoutError('synthetic secret'), ApiErrorCode.TIMEOUT),
    (ssl.SSLError('synthetic secret'), ApiErrorCode.TLS_ERROR),
    (ssl.SSLCertVerificationError('synthetic secret'), ApiErrorCode.TLS_ERROR),
    (OSError('synthetic secret'), ApiErrorCode.TRANSPORT_ERROR),
    (RuntimeError('synthetic secret'), ApiErrorCode.TRANSPORT_ERROR),
])
@pytest.mark.parametrize('phase', ['open', 'read'])
def test_transport_errors_private_closed_and_single_attempt(error, code, phase, capsys):
    transport = (FakeTransport(error=error) if phase == 'open'
                 else FakeTransport(FakeResponse(document(), read_error=error)))
    result = assert_error(transport, code)
    assert result.__context__ is None and result.__cause__ is None
    assert 'synthetic secret' not in ''.join(traceback.format_exception(result))
    assert 'synthetic secret' not in capsys.readouterr().err


def test_total_deadline_detected_after_open_and_after_read(monkeypatch):
    now = [0.0]
    monkeypatch.setattr('sarex_loader.api_client.time.monotonic', lambda: now[0])
    for phase in ('open', 'read'):
        now[0] = 0.0
        transport = FakeTransport()
        if phase == 'open':
            original = transport.open

            def late_open(request, original=original):
                now[0] = 31.0
                return original(request)

            transport.open = late_open
        else:
            original_read = transport.response.read

            def late_read(size, *, timeout, original=original_read):
                now[0] = 31.0
                return original(size, timeout=timeout)

            transport.response.read = late_read
        assert_error(transport, ApiErrorCode.TIMEOUT)


@pytest.mark.parametrize('body', [b'', b'{', b'<html>not json</html>', b'\xff',
                                  b'{"id":7,"id":8}', b'{"n":NaN}', b'{"n":Infinity}',
                                  b'{"n":1e999}', b'[' * 33 + b']' * 33,
                                  b'{"n":' + b'1' * 100 + b'}'])
def test_malformed_json_and_resource_bounds(body):
    assert_error(FakeTransport(FakeResponse(body=body)), ApiErrorCode.INVALID_RESPONSE)


@pytest.mark.parametrize('value', [
    None, [], {}, document(identifier=True), document(identifier='7'), document(identifier=8),
    document(identifier=0), document(identifier=2**63), document(name=''), document(name=12),
    document(is_folder=1), document(path=None), document(files=None), document(files=['8']),
    document(files=[True]), document(files=[8, 8]), document(files=[7]),
    document(files=[8], folders=[8]), document(folders={}),
    document(name='\ud800'), document(name='unsafe\u202e'), document(name='x' * 8193),
    document(extra=[0] * 10_001), document(extra=[[0] * 9000 for _ in range(6)]),
])
def test_invalid_document_types_identity_and_collections(value):
    assert_error(FakeTransport(FakeResponse(value)), ApiErrorCode.INVALID_RESPONSE)


@pytest.mark.parametrize('headers', [
    {}, {'Content-Type': 'text/html'}, {'Content-Type': 'application/json; charset=latin1'},
    {'Content-Type': 'application/json', 'Content-Encoding': 'gzip'},
    {'Content-Type': 'application/json', 'content-type': 'application/json'},
    {'Content-Type': 'application/json', 'Content-Length': '-1'},
    {'Content-Type': 'application/json', 'Content-Length': '0'},
    {'Content-Type': 'application/json', 'X-Test': 'bad\r\nheader'},
    {'Content-Type': 'application/json', 'X-Test': 123},
    {f'X-{i}': 'value' for i in range(65)},
])
def test_invalid_headers_and_length_mismatch(headers):
    assert_error(FakeTransport(FakeResponse(document(), headers=headers)),
                 ApiErrorCode.INVALID_RESPONSE)


def test_streaming_limit_with_and_without_content_length():
    transport = FakeTransport(FakeResponse(body=b'x' * 1000))
    assert_error(transport, ApiErrorCode.RESPONSE_TOO_LARGE, max_response_bytes=100)
    assert transport.response.offset == 101
    transport = FakeTransport(FakeResponse(document(), headers={
        'Content-Type': 'application/json', 'Content-Length': '101',
    }))
    assert_error(transport, ApiErrorCode.RESPONSE_TOO_LARGE, max_response_bytes=100)
    assert not transport.response.reads
    transport = FakeTransport(FakeResponse(document(), headers={
        'Content-Type': 'application/json', 'X-Huge': 'x' * 32769,
    }))
    assert_error(transport, ApiErrorCode.RESPONSE_TOO_LARGE)


def test_exact_limit_valid_length_and_content_type_case():
    body = json.dumps(document()).encode()
    transport = FakeTransport(FakeResponse(body=body, headers={
        'Content-Type': 'Application/JSON; charset=UTF-8', 'Content-Length': str(len(body)),
    }))
    assert client(transport, max_response_bytes=len(body)).get_document(7).id == 7


@pytest.mark.parametrize('url', [
    'http://api.example.invalid', 'https://user:password@api.example.invalid',
    ORIGIN + '?secret=x', ORIGIN + '#fragment', ORIGIN + '/..', ORIGIN + '/api/../other',
    ORIGIN + '/%2e%2e', ORIGIN + '\\other', ORIGIN + '\n', 'https://localhost',
    'https://127.0.0.1', 'https://169.254.169.254', 'https://[::1]', 'https://2130706433',
    'https://api.example.invalid.', 'https://api.example.invalid:0',
    'https://api.example.invalid:99999', 'https://домен.invalid',
])
def test_unsafe_base_urls_rejected_before_transport(url):
    with pytest.raises(ValidationError):
        ApiSettings(url, (ORIGIN,))


def test_unknown_origin_port_wildcards_and_missing_allowlist():
    for allowed in [(), ('https://other.invalid',), ('https://*.example.invalid',),
                    (ORIGIN + '/api',), (ORIGIN + ':444',), [ORIGIN]]:
        with pytest.raises(ValidationError):
            ApiSettings(ORIGIN, allowed)


@pytest.mark.parametrize('value', [True, '7', 0, -1, 2**63, None, '7/ancestors', '../1'])
def test_invalid_ids_and_no_arbitrary_endpoints(value):
    transport = FakeTransport()
    instance = client(transport)
    for method in (instance.get_document, instance.get_ancestors):
        with pytest.raises(ValidationError):
            method(value)
    with pytest.raises(ValidationError):
        instance._read('/internal/v1/documents/{document_id}', 7)
    assert not transport.requests
    assert not hasattr(instance, 'post') and not hasattr(instance, 'delete')


@pytest.mark.parametrize('value', ['', 'Bearer synthetic', 'a b', 'a\r\nb', 'a\x00b',
                                  'кириллица', 'x' * 4097, None])
def test_invalid_authorization_and_repr(value):
    with pytest.raises(ValidationError):
        BearerToken(value)
    assert 'synthetic-sentinel' not in repr(BearerToken('synthetic-sentinel'))


@pytest.mark.parametrize('value', [0, -1, True, None, float('nan'), float('inf'), 301, '5'])
def test_invalid_timeouts(value):
    for field in ('connect', 'read', 'total'):
        with pytest.raises(ValidationError):
            Timeouts(**{field: value})


def test_limits_and_insecure_tls_context_fail_closed(monkeypatch):
    for value in [0, True, '100', 8 * 1024**2 + 1]:
        with pytest.raises(ValidationError):
            ApiSettings(ORIGIN, (ORIGIN,), max_response_bytes=value)
    with pytest.raises(ValidationError):
        Timeouts(connect=10, total=5)
    context = SimpleNamespace(verify_mode=ssl.CERT_NONE, check_hostname=False)
    monkeypatch.setattr('sarex_loader.api_client._tls_context', lambda: context)
    transport = FakeTransport()
    with pytest.raises(ApiError, match='TLS_ERROR'):
        client(transport).get_document(7)
    assert not transport.requests


def test_default_offline_and_network_enabled_transport_rejected():
    with pytest.raises(ApiError, match='NETWORK_DISABLED'):
        client().get_document(7)
    transport = FakeTransport()
    transport.network_enabled = True
    with pytest.raises(ApiError, match='NETWORK_DISABLED'):
        client(transport).get_document(7)
    assert not transport.requests


def test_no_token_or_server_data_in_logs_errors_or_models(capsys):
    sentinel = 'SYNTHETIC_SENSITIVE_SENTINEL'
    transport = FakeTransport(FakeResponse(document(name=sentinel, public_link=sentinel)))
    instance = SarexClient(ApiSettings(ORIGIN, (ORIGIN,)), BearerToken(sentinel),
                           transport=transport)
    result = instance.get_document(7)
    captured = capsys.readouterr()
    assert sentinel not in captured.out + captured.err + repr(instance) + repr(result)
    assert sentinel not in repr(transport.requests)


def test_close_error_and_interruption_do_not_retry_or_leak(monkeypatch):
    transport = FakeTransport()

    def broken_close():
        raise OSError('SYNTHETIC_PRIVATE_ERROR')

    monkeypatch.setattr(transport.response, 'close', broken_close)
    with pytest.raises(ApiError, match='TRANSPORT_ERROR') as error:
        client(transport).get_document(7)
    assert error.value.__context__ is None and len(transport.requests) == 1
    transport = FakeTransport(FakeResponse(document(), read_error=KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        client(transport).get_document(7)
    assert transport.response.closed and len(transport.requests) == 1


def test_tls_key_logging_proxy_and_auth_environment_are_not_used(monkeypatch, tmp_path):
    keylog = tmp_path / 'keys.txt'
    monkeypatch.setenv('SSLKEYLOGFILE', str(keylog))
    monkeypatch.setenv('HTTPS_PROXY', 'https://untrusted.invalid')
    monkeypatch.setenv('SAREX_TOKEN', 'SYNTHETIC_UNUSED_ENVIRONMENT_VALUE')
    transport = FakeTransport()
    assert client(transport).get_document(7).id == 7
    assert transport.requests[0].tls_context.keylog_filename is None
    assert transport.requests[0].headers['Authorization'] == 'Bearer synthetic-test-only'
    assert not keylog.exists()


@pytest.mark.parametrize('override', [
    {'check_hostname': False}, {'minimum_version': ssl.TLSVersion.TLSv1_1},
    {'keylog_filename': 'synthetic-forbidden-keylog'},
])
def test_each_tls_invariant_is_enforced_before_open(monkeypatch, override):
    values = {'verify_mode': ssl.CERT_REQUIRED, 'check_hostname': True,
              'minimum_version': ssl.TLSVersion.TLSv1_2, 'keylog_filename': None}
    context = SimpleNamespace(**{**values, **override})
    monkeypatch.setattr('sarex_loader.api_client._tls_context', lambda: context)
    transport = FakeTransport()
    with pytest.raises(ApiError, match='TLS_ERROR'):
        client(transport).get_document(7)
    assert not transport.requests


@pytest.mark.parametrize('value', ['not bytes', None, b'x' * 65537])
def test_transport_read_contract_violation_is_rejected_and_closed(monkeypatch, value):
    transport = FakeTransport()
    monkeypatch.setattr(transport.response, 'read', lambda *args, **kwargs: value)
    assert_error(transport, ApiErrorCode.INVALID_RESPONSE)
