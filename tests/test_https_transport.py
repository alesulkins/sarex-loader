"""Real HTTP framing, fake DNS/TCP/TLS only. No real sockets/listeners or credentials."""

import io
import ipaddress
import json
import socket
import ssl
import threading
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest

from sarex_loader.api_client import ApiSettings, SarexClient, Timeouts, _tls_context
from sarex_loader.api_models import ApiError
from sarex_loader.api_transport import BearerToken, GetRequest, JsonBody, PostRequest
from sarex_loader.auth import AuthSession
from sarex_loader.https_transport import ReadOnlyHTTPSTransport
from sarex_loader.read_only_api import main
from sarex_loader.read_only_policy import (
    AUTH_BASE,
    DOCUMENTATION_BASE,
    ReadOnlyPolicy,
    load_read_only_policy,
)
from sarex_loader.safety import ValidationError
from tests.test_api_client import forbid_network as forbid_network

PUBLIC = '93.184.216.34'  # A mocked global IP; never contacted.
DOC = {'id': 7, 'name': 'Synthetic PDF', 'is_folder': False}


def wire(value=DOC, *, status=200, body=None, headers=None):
    body = json.dumps(value).encode() if body is None else body
    headers = [('Content-Type', 'application/json'), ('Content-Length', str(len(body)))] \
        if headers is None else headers
    return (f'HTTP/1.1 {status} Synthetic\r\n'.encode()
            + b''.join(f'{key}: {value}\r\n'.encode() for key, value in headers)
            + b'\r\n' + body)


class FakeSocket:
    def __init__(self, harness):
        self.harness = harness
        self.closed = False
        self.sent = bytearray()
        self.timeouts = []
        self.stopped = threading.Event()
        self.file = None

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def connect(self, target):
        self.target = target
        self.harness.connected.append(target)
        if self.harness.connect_error:
            raise self.harness.connect_error

    def getpeername(self):
        return self.harness.peer or self.target

    def do_handshake(self):
        if self.harness.tls_error:
            raise self.harness.tls_error

    def sendall(self, data):
        self.sent.extend(data)
        if self.harness.send_error:
            raise self.harness.send_error

    def makefile(self, *_args):
        payload = self.harness.responses.pop(0)
        owner = self

        class Stream(io.BytesIO):
            def readline(self, *args):
                if owner.harness.hang_headers:
                    owner.stopped.wait(1)
                    raise OSError('SYNTHETIC_SENSITIVE_HEADER_ERROR')
                return super().readline(*args)

            def read1(self, size):
                if owner.harness.hang_body:
                    owner.stopped.wait(1)
                    raise OSError('SYNTHETIC_SENSITIVE_BODY_ERROR')
                return super().read1(size)

        self.file = Stream(payload)
        return self.file

    def shutdown(self, _how):
        self.stopped.set()

    def close(self):
        self.closed = True


@pytest.fixture
def https_mock(monkeypatch):
    class Harness:
        def __init__(self):
            self.responses = [wire()]
            self.dns_calls, self.connected, self.sockets, self.tls = [], [], [], []
            self.addresses = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                               '', (PUBLIC, 443))]
            self.connect_error = self.tls_error = self.send_error = None
            self.peer = None
            self.hang_headers = self.hang_body = False

        def resolve(self, host, port, **kwargs):
            self.dns_calls.append((host, port, kwargs))
            return self.addresses

        def socket(self, *args):
            sock = FakeSocket(self)
            self.sockets.append(sock)
            return sock

        def wrap(self, context, sock, *, server_hostname, do_handshake_on_connect):
            self.tls.append((context, server_hostname, do_handshake_on_connect))
            return sock

    harness = Harness()
    monkeypatch.setattr(socket, 'getaddrinfo', harness.resolve)
    monkeypatch.setattr(socket, 'socket', harness.socket)
    monkeypatch.setattr(ssl.SSLContext, 'wrap_socket',
                        lambda context, sock, **kw: harness.wrap(context, sock, **kw))
    return harness


def setup(policy=None, **kwargs):
    policy = policy or ReadOnlyPolicy((7,), allow_document_types=True, allow_ancestors=True,
                                      max_requests=8)
    transport = ReadOnlyHTTPSTransport(policy, confirmed=True)
    client = SarexClient(ApiSettings(DOCUMENTATION_BASE, ('https://api.sarex.io',),
                                     timeouts=policy.timeouts,
                                     max_response_bytes=policy.max_response_bytes),
                         BearerToken('SYNTHETIC-ACCESS'), transport=transport,
                         read_only_network_enabled=True, **kwargs)
    return transport, client


def request(url=DOCUMENTATION_BASE + '/v1/documents/7', *, method='GET', body=None):
    headers = {'Accept': 'application/json', 'Accept-Encoding': 'identity'}
    if method == 'GET':
        headers['Authorization'] = 'Bearer SYNTHETIC-ACCESS'
    elif body is not None:
        headers.update({'Content-Type': 'application/json',
                        'Content-Length': str(body.content_length)})
    args = dict(url=url, headers=headers, tls_context=_tls_context(), connect_timeout=1,
                read_timeout=1, deadline=time.monotonic() + 3)
    return GetRequest(**args) if method == 'GET' else PostRequest(**args, body=body)


def test_document_https_exact_request_and_pinned_tls(https_mock, monkeypatch, capsys):
    monkeypatch.setenv('HTTPS_PROXY', 'https://SYNTHETIC-SECRET.invalid')
    monkeypatch.setenv('SSLKEYLOGFILE', '/nonexistent/SYNTHETIC-KEYLOG')
    transport, client = setup()
    assert client.get_document(7).id == 7
    assert https_mock.connected == [(PUBLIC, 443)]
    context, sni, handshake = https_mock.tls[0]
    assert sni == 'api.sarex.io' and handshake is False
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert context.keylog_filename is None
    sent = bytes(https_mock.sockets[0].sent)
    assert sent.startswith(b'GET /documentations/api/v1/documents/7 HTTP/1.1\r\n')
    assert b'Host: api.sarex.io' in sent and b'Authorization: Bearer SYNTHETIC-ACCESS' in sent
    assert b'Cookie:' not in sent and b'Proxy' not in sent
    assert all(s.closed and s.file.closed for s in https_mock.sockets)
    assert len(https_mock.dns_calls) == 1
    output = capsys.readouterr()
    assert 'SYNTHETIC' not in output.out + output.err + repr(transport)


def test_auth_refresh_then_get_uses_same_closed_allowlist(https_mock, capsys):
    https_mock.responses = [wire({'access': 'SYNTHETIC-OLD', 'refresh': 'SYNTHETIC-REFRESH'}),
                            wire({'access': 'SYNTHETIC-NEW'}), wire()]
    policy = ReadOnlyPolicy((7,), max_requests=3)
    transport = ReadOnlyHTTPSTransport(policy, confirmed=True)
    now = [0]
    session = AuthSession(ApiSettings(AUTH_BASE, ('https://lk.sarex.io',)), transport=transport,
                          clock=lambda: now[0], read_only_network_enabled=True)
    session.login('SYNTHETIC-USER', 'SYNTHETIC-PASSWORD')
    now[0] = 300
    client = SarexClient(ApiSettings(DOCUMENTATION_BASE, ('https://api.sarex.io',)),
                         token_provider=session.access_token, transport=transport,
                         read_only_network_enabled=True)
    assert client.get_document(7).id == 7
    payloads = [bytes(s.sent) for s in https_mock.sockets]
    assert payloads[0].startswith(b'POST /api/token/ HTTP/1.1')
    assert payloads[1].startswith(b'POST /api/token/refresh/ HTTP/1.1')
    assert all(b'Authorization:' not in value for value in payloads[:2])
    assert json.loads(payloads[0].split(b'\r\n\r\n')[1]) == {
        'username': 'SYNTHETIC-USER', 'password': 'SYNTHETIC-PASSWORD'}
    assert json.loads(payloads[1].split(b'\r\n\r\n')[1]) == {'refresh': 'SYNTHETIC-REFRESH'}
    assert b'Bearer SYNTHETIC-NEW' in payloads[2]
    assert [v[1] for v in https_mock.tls] == ['lk.sarex.io', 'lk.sarex.io', 'api.sarex.io']
    output = capsys.readouterr()
    assert 'SYNTHETIC' not in output.out + output.err


@pytest.mark.parametrize('status,code', [(401, 'AUTHENTICATION'), (403, 'ACCESS_DENIED'),
                                       (404, 'NOT_FOUND'), (429, 'RATE_LIMITED'),
                                       (500, 'SERVER_ERROR')])
@pytest.mark.parametrize('auth', [False, True])
def test_http_errors_do_not_retry_or_leak(https_mock, capsys, status, code, auth):
    https_mock.responses = [wire(body=b'SYNTHETIC-SECRET', status=status)]
    transport, client = setup()
    with pytest.raises(ApiError) as result:
        if auth:
            session = AuthSession(ApiSettings(AUTH_BASE, ('https://lk.sarex.io',)),
                                  transport=transport, read_only_network_enabled=True)
            session.login('SYNTHETIC-USER', 'SYNTHETIC-PASSWORD')
        else:
            client.get_document(7)
    assert result.value.code.value == code
    assert len(https_mock.sockets) == 1
    assert all(s.closed and s.file.closed for s in https_mock.sockets)
    output = capsys.readouterr()
    assert 'SYNTHETIC' not in str(result.value) + output.out + output.err
    assert result.value.__context__ is None


@pytest.mark.parametrize('operation', ['types', 'ancestors'])
def test_documented_reads_only(https_mock, operation):
    transport, client = setup()
    if operation == 'types':
        https_mock.responses = [wire([{'name': 'pdf', 'fields': []}])]
        assert len(client.get_document_types()) == 1
    else:
        https_mock.responses = [wire([{'id': 3, 'name': 'Synthetic folder', 'is_folder': True}])]
        assert client.get_ancestors(7)[0].id == 3
    assert len(https_mock.sockets) == 1  # Returned parent IDs do not trigger any new request.


@pytest.mark.parametrize('url', [
    DOCUMENTATION_BASE + '/v1/documents', DOCUMENTATION_BASE + '/v1/bundles',
    DOCUMENTATION_BASE + '/v1/bundles/b/pdf/upload_single',
    DOCUMENTATION_BASE + '/v1/bundles/b/upload_finish',
    DOCUMENTATION_BASE + '/v1/documents/7/add_bundle',
    DOCUMENTATION_BASE + '/v1/uploads/multipart/u/complete',
    DOCUMENTATION_BASE + '/internal/v1/documents/7',
])
def test_resource_posts_blocked_at_transport_before_dns(https_mock, url):
    transport, _ = setup()
    body = JsonBody({'synthetic': 'data'})
    with pytest.raises(ApiError, match='WRITES_DISABLED'):
        transport.open(request(url, method='POST', body=body))
    assert not https_mock.dns_calls and not https_mock.sockets
    assert body._data == b''


@pytest.mark.parametrize('method', ['DELETE', 'PUT', 'PATCH', 'HEAD', 'OPTIONS'])
def test_arbitrary_http_verbs_cannot_bypass_transport(https_mock, method):
    transport, _ = setup()
    req = request()
    object.__setattr__(req, 'method', method)  # Attack even frozen dataclass invariants.
    with pytest.raises(ApiError):
        transport.open(req)
    assert not https_mock.dns_calls


@pytest.mark.parametrize('url', [
    'http://api.sarex.io/documentations/api/v1/documents/7',
    'https://api.sarex.io.evil.invalid/documentations/api/v1/documents/7',
    'https://api.sarex.io@evil.invalid/documentations/api/v1/documents/7',
    'https://127.0.0.1/documentations/api/v1/documents/7',
    'https://api.sarex.io:444/documentations/api/v1/documents/7',
    DOCUMENTATION_BASE + '/v1/documents/7?extend=bundles',
    DOCUMENTATION_BASE + '/v1/documents/7#ignored',
    DOCUMENTATION_BASE + '/v1/documents/%37',
    DOCUMENTATION_BASE + '/v1/documents/../7',
    DOCUMENTATION_BASE + '/v1//documents/7',
    DOCUMENTATION_BASE + '/v1/documents/8',
    DOCUMENTATION_BASE + '/v1/documents/7/download',
    DOCUMENTATION_BASE + '/v1/disks',
    AUTH_BASE + '/token/',
])
def test_ssrf_url_and_scope_rejected_before_dns(https_mock, url):
    transport, _ = setup()
    with pytest.raises(ApiError):
        transport.open(request(url))
    assert not https_mock.dns_calls


@pytest.mark.parametrize('ip', ['127.0.0.1', '10.0.0.1', '169.254.169.254', '192.168.1.1',
                              '100.64.0.1', str(ipaddress.IPv4Address(0)), '224.0.0.1', '::1',
                              'fc00::1', 'fe80::1', '::ffff:127.0.0.1',
                              '64:ff9b::7f00:1', '2002:7f00:1::1'])
def test_private_dns_and_transition_ips_rejected(https_mock, ip):
    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
    address = (ip, 443, 0, 0) if ':' in ip else (ip, 443)
    https_mock.addresses.append((family, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', address))
    _, client = setup()
    with pytest.raises(ApiError, match='ACCESS_DENIED'):
        client.get_document(7)
    assert not https_mock.connected and not https_mock.sockets


def test_peer_address_must_match_pinned_dns(https_mock):
    https_mock.peer = ('127.0.0.1', 443)
    _, client = setup()
    with pytest.raises(ApiError, match='ACCESS_DENIED'):
        client.get_document(7)
    assert not https_mock.tls and not https_mock.sockets[0].sent


@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
def test_redirects_including_same_host_are_never_followed(https_mock, status):
    https_mock.responses = [wire(status=status, headers=[
        ('Location', AUTH_BASE + '/token/?SYNTHETIC-SECRET'), ('Content-Length', '0')], body=b'')]
    transport, _ = setup()
    with pytest.raises(ApiError, match='REDIRECT_REJECTED') as error:
        transport.open(request())
    assert len(https_mock.dns_calls) == 1 and len(https_mock.sockets) == 1
    assert 'SYNTHETIC' not in str(error.value)
    assert error.value.__context__ is None


@pytest.mark.parametrize('failure,code', [('tls', 'TLS_ERROR'), ('connect', 'TIMEOUT'),
                                        ('send', 'TRANSPORT_ERROR')])
def test_tls_timeout_disconnect_no_retry(https_mock, failure, code):
    error = ssl.SSLError('SYNTHETIC-SECRET') if failure == 'tls' else (
        TimeoutError('SYNTHETIC-SECRET') if failure == 'connect'
        else ConnectionResetError('SYNTHETIC-SECRET'))
    setattr(https_mock, failure + '_error', error)
    transport, _ = setup()
    with pytest.raises(ApiError, match=code) as caught:
        transport.open(request())
    assert len(https_mock.connected) == 1
    assert all(s.closed for s in https_mock.sockets)
    assert caught.value.__context__ is None


@pytest.mark.parametrize('body', [b'{', b'{"id":7,"id":8}', b'[]', b'{"id":true}', b'\xff'])
def test_corrupt_json_or_document_rejected(https_mock, body):
    https_mock.responses = [wire(body=body)]
    _, client = setup()
    with pytest.raises(ApiError, match='INVALID_RESPONSE'):
        client.get_document(7)
    assert len(https_mock.sockets) == 1


@pytest.mark.parametrize('response', [
    wire(headers=[('Content-Length', '10'), ('Content-Length', '10')]),
    wire(headers=[('Content-Length', '1'), ('Transfer-Encoding', 'chunked')]),
    wire(headers=[('Content-Length', '99999999')]),
    wire(headers=[('Content-Encoding', 'gzip')]),
    wire(headers=[('X-Long', 'x' * 9000)]),
    wire(headers=[('X-' + str(i), 'x' * 1000) for i in range(40)]),
    wire(headers=[('X-' + str(i), 'x') for i in range(65)]),
    wire(headers=[('Content-Length', '1000')], body=b'{}'),
])
def test_bounded_headers_framing_and_truncation(https_mock, response):
    https_mock.responses = [response]
    transport, _ = setup()
    with pytest.raises(ApiError):
        result = transport.open(request())
        try:
            while result.read(65536, timeout=1):
                pass
        finally:
            result.close()
    assert all(s.closed for s in https_mock.sockets)


def test_chunked_bytes_limit_is_enforced_by_transport_itself(https_mock):
    https_mock.responses = [wire(headers=[('Transfer-Encoding', 'chunked')],
                                body=b'20\r\n' + b'x' * 32 + b'\r\n0\r\n\r\n')]
    transport, _ = setup(ReadOnlyPolicy((7,), max_response_bytes=16))
    result = transport.open(request())
    with pytest.raises(ApiError, match='RESPONSE_TOO_LARGE'):
        result.read(65536, timeout=1)
    assert https_mock.sockets[0].closed


@pytest.mark.parametrize('phase', ['headers', 'body'])
def test_total_deadline_interrupts_blocked_io(https_mock, phase):
    setattr(https_mock, 'hang_' + phase, True)
    policy = ReadOnlyPolicy((7,), timeouts=Timeouts(.1, .1, .15))
    _, client = setup(policy)
    started = time.monotonic()
    with pytest.raises(ApiError, match='TIMEOUT'):
        client.get_document(7)
    assert time.monotonic() - started < .8
    assert all(s.closed and s.stopped.is_set() for s in https_mock.sockets)


def test_dns_timeout_cannot_connect_late_or_spawn_unbounded_workers(https_mock, monkeypatch):
    released = threading.Event()
    def delayed(*args, **kwargs):
        released.wait(1)
        return https_mock.resolve(*args, **kwargs)
    monkeypatch.setattr(socket, 'getaddrinfo', delayed)
    transport, _ = setup(ReadOnlyPolicy((7,), timeouts=Timeouts(.03, .03, .1)))
    try:
        for _ in range(2):
            with pytest.raises(ApiError, match='TIMEOUT'):
                transport.open(request())
        assert not https_mock.sockets
    finally:
        released.set()
        transport._dns._worker.join(1)
    assert len(https_mock.dns_calls) == 1 and not https_mock.sockets


def test_default_off_and_live_client_gate_preserved(https_mock):
    transport = ReadOnlyHTTPSTransport(ReadOnlyPolicy((7,)))
    with pytest.raises(ApiError, match='NETWORK_DISABLED'):
        transport.open(request())
    armed, _ = setup()
    client = SarexClient(ApiSettings(DOCUMENTATION_BASE, ('https://api.sarex.io',)),
                         BearerToken('SYNTHETIC'), transport=armed)
    with pytest.raises(ApiError, match='NETWORK_DISABLED'):
        client.get_document(7)
    assert not https_mock.dns_calls


def test_write_blocked_before_token_provider_even_with_mock_write_flag(https_mock):
    transport, _ = setup()
    provider = Mock(side_effect=AssertionError('No token refresh'))
    client = SarexClient(ApiSettings(DOCUMENTATION_BASE, ('https://api.sarex.io',)),
                         token_provider=provider, transport=transport,
                         mock_writes_enabled=True, read_only_network_enabled=True)
    with pytest.raises(ApiError, match='WRITES_DISABLED'):
        client.create_document(disk_id='synthetic', parent_id=1, name='scan.pdf',
                               bundle_id='bundle')
    assert not provider.called and not https_mock.dns_calls


def test_request_limit_and_explicit_scope(https_mock):
    transport, client = setup(ReadOnlyPolicy((7,), max_requests=1))
    assert client.get_document(7).id == 7
    for call in [lambda: client.get_document(7), client.get_document_types,
                 lambda: client.get_ancestors(7)]:
        with pytest.raises(ApiError, match='ACCESS_DENIED'):
            call()
    assert len(https_mock.sockets) == 1


@pytest.mark.parametrize('change', ['cookie', 'host', 'auth_newline', 'redirect', 'retry',
                                  'environment', 'tls_hostname', 'tls_cert'])
def test_request_security_flags_cannot_be_weakened(https_mock, change):
    transport, _ = setup()
    req = request()
    if change in {'cookie', 'host'}:
        req.headers[change.title()] = 'SYNTHETIC'
    elif change == 'auth_newline':
        req.headers['Authorization'] = 'Bearer SYNTHETIC\r\nX: y'
    elif change == 'tls_hostname':
        req.tls_context.check_hostname = False
    elif change == 'tls_cert':
        req.tls_context.check_hostname = False
        req.tls_context.verify_mode = ssl.CERT_NONE
    else:
        field = {'redirect': 'follow_redirects', 'retry': 'retries',
                 'environment': 'trust_environment'}[change]
        object.__setattr__(req, field, True)
    with pytest.raises(ApiError):
        transport.open(req)
    assert not https_mock.dns_calls


def test_auth_schema_rejects_extra_fields_and_declared_length_mismatch(https_mock):
    for data, length in [({'username': 'synthetic', 'password': 'synthetic', 'url': 'bad'}, None),
                         ({'username': 'synthetic', 'password': 'synthetic'}, 1)]:
        body = JsonBody(data)
        if length is not None:
            body.content_length = length
        transport, _ = setup()
        with pytest.raises(ApiError):
            transport.open(request(AUTH_BASE + '/token/', method='POST', body=body))
        assert body._data == b''
    assert not https_mock.dns_calls


def test_manual_preview_reads_no_secrets_and_attempts_no_network(tmp_path, monkeypatch, capsys):
    path = Path(__file__).resolve().parents[1] / 'read_only_api.example.toml'
    prompt = Mock(side_effect=AssertionError('Credentials must not be requested'))
    monkeypatch.setattr('getpass.getpass', prompt)
    monkeypatch.setattr('builtins.input', prompt)
    assert main(['--config', str(path), '--document-id', '6391661']) == 0
    assert json.loads(capsys.readouterr().out)['network_started'] is False
    assert not prompt.called
    # Even with the flag, non-interactive execution refuses before prompting.
    monkeypatch.setattr('sys.stdin.isatty', lambda: False)
    assert main(['--config', str(path), '--document-id', '6391661', '--confirm-read-only']) == 2
    assert not prompt.called


def test_manual_wrong_confirmation_never_asks_for_login(monkeypatch):
    path = Path(__file__).resolve().parents[1] / 'read_only_api.example.toml'
    monkeypatch.setattr('sys.stdin.isatty', lambda: True)
    monkeypatch.setattr('sys.stderr.isatty', lambda: True)
    monkeypatch.setattr('builtins.input', lambda: 'NO')
    prompt = Mock(side_effect=AssertionError('No credentials'))
    monkeypatch.setattr('getpass.getpass', prompt)
    assert main(['--config', str(path), '--document-id', '6391661', '--confirm-read-only']) == 2
    assert not prompt.called


def test_policy_rejects_secret_fields_custom_hosts_and_wrong_types(tmp_path):
    sample = (Path(__file__).resolve().parents[1] / 'read_only_api.example.toml').read_text()
    path = tmp_path / 'read-only.toml'
    for text in [sample.replace('mode = "read-only"', 'password="SYNTHETIC"\nmode="read-only"'),
                 sample.replace('api.sarex.io', 'evil.invalid'),
                 sample.replace('[6391661]', '[true]'), sample.replace('mode = "read-only"',
                                                                          'mode = "write"')]:
        path.write_text(text)
        with pytest.raises(ValidationError):
            load_read_only_policy(path)
    env = tmp_path / '.env'
    env.write_text('SYNTHETIC')
    with pytest.raises(ValidationError):
        load_read_only_policy(env)
    with pytest.raises(ValidationError):
        replace(ReadOnlyPolicy((7,)), document_ids=(7, 7))


@pytest.mark.parametrize('failure', [401, 403, 404, 429, 500, 'malformed', 'rotation'])
def test_refresh_failure_invalidates_session_without_retry(https_mock, failure):
    login = wire({'access': 'SYNTHETIC-OLD', 'refresh': 'SYNTHETIC-REFRESH'})
    if failure == 'malformed':
        response = wire(body=b'{')
    elif failure == 'rotation':
        response = wire({'access': 'SYNTHETIC-NEW', 'refresh': 'SYNTHETIC-ROTATED'})
    else:
        response = wire({}, status=failure)
    https_mock.responses = [login, response]
    transport, _ = setup()
    now = [0]
    auth = AuthSession(ApiSettings(AUTH_BASE, ('https://lk.sarex.io',)), transport=transport,
                       clock=lambda: now[0], read_only_network_enabled=True)
    auth.login('synthetic', 'synthetic')
    now[0] = 300
    with pytest.raises(ApiError):
        auth.access_token()
    with pytest.raises(ApiError, match='REAUTH_REQUIRED'):
        auth.access_token()
    assert len(https_mock.sockets) == 2
    assert auth._access is None and auth._refresh is None


def test_ca_environment_and_caller_trust_store_do_not_override_transport(https_mock, monkeypatch,
                                                                      tmp_path):
    certificate = tmp_path / 'untrusted.pem'
    certificate.write_text('SYNTHETIC: not a certificate')
    monkeypatch.setenv('SSL_CERT_FILE', str(certificate))
    monkeypatch.setenv('SSL_CERT_DIR', str(tmp_path))
    transport, _ = setup()
    req = request()
    response = transport.open(req)
    response.close()
    assert https_mock.tls[0][0] is not req.tls_context
    assert https_mock.tls[0][0].cert_store_stats()['x509_ca'] > 0


def test_non_json_content_type_and_invalid_chunked_stream_fail_closed(https_mock):
    for response in [wire(headers=[('Content-Type', 'text/html')], body=b'<html>bad</html>'),
                     wire(headers=[('Content-Type', 'application/json'),
                                   ('Transfer-Encoding', 'chunked')], body=b'INVALID\r\n')]:
        https_mock.responses = [response]
        _, client = setup()
        with pytest.raises(ApiError):
            client.get_document(7)


def test_network_flag_does_not_authorize_an_arbitrary_adapter(https_mock):
    adapter = Mock(network_enabled=True)
    client = SarexClient(ApiSettings(DOCUMENTATION_BASE, ('https://api.sarex.io',)),
                         BearerToken('SYNTHETIC'), transport=adapter,
                         read_only_network_enabled=True)
    with pytest.raises(ApiError, match='NETWORK_DISABLED'):
        client.get_document(7)
    assert not adapter.open.called and not https_mock.dns_calls


def test_no_auto_get_retry_after_authentication_error(https_mock):
    https_mock.responses = [wire({}, status=401)]
    provider = Mock(return_value=BearerToken('SYNTHETIC'))
    transport, _ = setup()
    client = SarexClient(ApiSettings(DOCUMENTATION_BASE, ('https://api.sarex.io',)),
                         token_provider=provider, transport=transport,
                         read_only_network_enabled=True)
    with pytest.raises(ApiError, match='AUTHENTICATION'):
        client.get_document(7)
    assert provider.call_count == 1 and len(https_mock.sockets) == 1


def test_manual_confirmed_flow_with_synthetic_credentials_only(https_mock, monkeypatch,
                                                             tmp_path, capsys):
    sample = Path(__file__).resolve().parents[1] / 'read_only_api.example.toml'
    config = tmp_path / 'readonly.toml'
    config.write_text(sample.read_text().replace('[6391661]', '[7]'))
    monkeypatch.setattr('sys.stdin.isatty', lambda: True)
    monkeypatch.setattr('sys.stderr.isatty', lambda: True)
    monkeypatch.setattr('builtins.input', lambda: 'READ ONLY document 7')
    monkeypatch.setattr('getpass.getpass',
                        Mock(side_effect=['SYNTHETIC-USER', 'SYNTHETIC-PASSWORD']))
    https_mock.responses = [wire({'access': 'SYNTHETIC-ACCESS', 'refresh': 'SYNTHETIC-REFRESH'}),
                            wire()]
    assert main(['--config', str(config), '--document-id', '7', '--confirm-read-only']) == 0
    output = capsys.readouterr()
    assert 'READ_ONLY_RESPONSE_VALIDATED' in output.out
    assert 'SYNTHETIC' not in output.out + output.err
    assert 'Synthetic PDF' not in output.out + output.err
    assert len(https_mock.sockets) == 2


def test_http_connection_close_and_logging_debug_cannot_expose_headers(https_mock, monkeypatch,
                                                                    capsys):
    import http.client

    monkeypatch.setattr(http.client.HTTPConnection, 'debuglevel', 1)
    body = json.dumps(DOC).encode()
    https_mock.responses = [wire(body=body, headers=[('Content-Type', 'application/json'),
                                                     ('Content-Length', str(len(body))),
                                                     ('Connection', 'close')])]
    _, client = setup()
    assert client.get_document(7).id == 7
    output = capsys.readouterr()
    assert 'SYNTHETIC' not in output.out + output.err
    assert https_mock.sockets[0].file.closed


def test_expired_request_never_starts_dns(https_mock):
    transport, _ = setup()
    req = replace(request(), deadline=time.monotonic() - 1)
    with pytest.raises(ApiError, match='TIMEOUT'):
        transport.open(req)
    assert not https_mock.dns_calls and not https_mock.sockets


def test_policy_cannot_be_replaced_or_subclassed_to_authorize_writes(https_mock):
    class UnsafePolicy(ReadOnlyPolicy):
        def authorize(self, method, url):
            raise AssertionError('Override must never be used')

    with pytest.raises(ApiError, match='ACCESS_DENIED'):
        ReadOnlyHTTPSTransport(UnsafePolicy((7,)), confirmed=True)
    transport, _ = setup()
    with pytest.raises(AttributeError):
        transport.policy = ReadOnlyPolicy((8,))
    for invalid in (None, 7, b'https://lk.sarex.io/api/token/'):
        with pytest.raises(ApiError, match='ACCESS_DENIED'):
            transport.policy.authorize('POST', invalid)
    assert not https_mock.dns_calls
