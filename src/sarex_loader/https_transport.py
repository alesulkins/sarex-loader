"""Explicitly armed HTTPS reads + token issuance only; no redirects/proxies/retries.

No network at import/construction. DNS is validated once per request; the socket
connects to that numeric address while TLS verifies the original approved hostname.
"""

import http.client
import ipaddress
import math
import queue
import re
import socket
import ssl
import threading
import time
from types import MappingProxyType

from sarex_loader.api_client import _tls_context
from sarex_loader.api_models import ApiError, ApiErrorCode, decode_payload
from sarex_loader.api_transport import BearerToken, GetRequest, JsonBody, PostRequest
from sarex_loader.gateway_diagnostic_policy import GatewayDiagnosticPolicy, GatewayLoginPolicy
from sarex_loader.gateway_tree_policy import GatewayTreeReadPolicy
from sarex_loader.read_only_policy import ReadOnlyPolicy
from sarex_loader.test_target_policy import SingleTestReadPolicy, TestTargetReadPolicy


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ApiError(ApiErrorCode.TIMEOUT)
    return remaining


def _close_quietly(resource):
    if resource is not None:
        try:
            resource.close()
        except Exception:
            return False  # Keep only a flag, never OS/TLS exception text.
    return True


def _public_address(text):
    address = ipaddress.ip_address(text)
    if (not address.is_global or address.is_private or address.is_reserved
            or address.is_multicast or address.is_loopback or address.is_link_local
            or address.is_unspecified):
        raise ApiError(ApiErrorCode.ACCESS_DENIED)
    if isinstance(address, ipaddress.IPv6Address) and (
        address not in ipaddress.ip_network('2000::/3') or address.ipv4_mapped
        or address.sixtofour or address.teredo or '%' in text
    ):
        raise ApiError(ApiErrorCode.ACCESS_DENIED)
    return address


class _DNS:
    def __init__(self):
        self._worker = None

    def resolve(self, host, deadline):
        # OS getaddrinfo has no portable timeout/cancellation. At most one outstanding
        # daemon resolver per transport; a timed-out result can never initiate HTTP.
        _remaining(deadline)
        if self._worker is not None and self._worker.is_alive():
            raise ApiError(ApiErrorCode.TIMEOUT)
        result = queue.Queue(maxsize=1)

        def lookup():
            try:
                addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM,
                                               proto=socket.IPPROTO_TCP)
                result.put(addresses)
            except Exception:
                result.put(None)  # Never retain/propagate OS error text.

        self._worker = threading.Thread(target=lookup, daemon=True)
        self._worker.start()
        try:
            addresses = result.get(timeout=_remaining(deadline))
        except queue.Empty:
            raise ApiError(ApiErrorCode.TIMEOUT) from None
        _remaining(deadline)
        if not isinstance(addresses, list) or not 1 <= len(addresses) <= 64:
            raise ApiError(ApiErrorCode.TRANSPORT_ERROR)
        for family, kind, protocol, _, target in addresses:
            if (not isinstance(target, tuple) or not target or not isinstance(target[0], str)
                    or len(target) != (2 if family == socket.AF_INET else 4)):
                raise ApiError(ApiErrorCode.ACCESS_DENIED)
            address = _public_address(target[0])
            if (family not in {socket.AF_INET, socket.AF_INET6} or kind != socket.SOCK_STREAM
                    or protocol != socket.IPPROTO_TCP or target[1] != 443
                    or (family == socket.AF_INET) != (address.version == 4)
                    or family == socket.AF_INET6 and target[2:] != (0, 0)):
                raise ApiError(ApiErrorCode.ACCESS_DENIED)
        # One address, one attempt. No fallback/retry on another IP after a failure.
        return addresses[0][0], addresses[0][4]


class _Deadline:
    def __init__(self, deadline):
        self.deadline = deadline
        self._sockets = []
        self._lock = threading.Lock()
        self.expired = False
        self.shutdown_failed = False
        self._timer = threading.Timer(_remaining(deadline), self._expire)
        self._timer.daemon = True
        self._timer.start()

    def add(self, sock):
        with self._lock:
            self._sockets.append(sock)
            if self.expired:
                sock.close()
                raise ApiError(ApiErrorCode.TIMEOUT)

    def _expire(self):
        with self._lock:
            self.expired = True
            for sock in self._sockets:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    self.shutdown_failed = True
                _close_quietly(sock)

    def close(self):
        self._timer.cancel()
        with self._lock:
            return all([_close_quietly(sock) for sock in self._sockets])


class _HeaderReader:
    def __init__(self, stream):
        self.stream = stream
        self.header_mode = True
        self.remaining = 32768
        self.framing_remaining = 32768

    def readline(self, size=-1):
        if not self.header_mode:
            line = self.stream.readline(min(size if size >= 0 else 8193, 8193))
            self.framing_remaining -= len(line)
            if len(line) > 8192 or self.framing_remaining < 0:
                raise ApiError(ApiErrorCode.RESPONSE_TOO_LARGE)
            return line
        line = self.stream.readline(min(size if size >= 0 else 8193, 8193, self.remaining + 1))
        self.remaining -= len(line)
        if self.remaining < 0 or len(line) > 8192:
            raise ApiError(ApiErrorCode.RESPONSE_TOO_LARGE)
        return line

    def __getattr__(self, name):
        return getattr(self.stream, name)


class _HTTPResponse(http.client.HTTPResponse):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fp = _HeaderReader(self.fp)

    def begin(self):
        reader = self.fp
        super().begin()
        reader.header_mode = False


class _Response:
    def __init__(self, response, connection, sock, guard, limit, read_timeout, release):
        self._response, self._connection, self._sock = response, connection, sock
        self._guard, self._limit, self._read_timeout = guard, limit, read_timeout
        self._release = release
        self._count = 0
        self._closed = False
        self.status = response.status
        headers = {}
        items = response.getheaders()
        if len(items) > 64 or response.headers.defects:
            raise ApiError(ApiErrorCode.RESPONSE_TOO_LARGE)
        for name, value in items:
            name = name.lower()
            if (name in headers or not re.fullmatch(r'[a-z0-9-]{1,128}', name)
                    or not value.isascii() or any(ord(c) < 32 or ord(c) == 127 for c in value)):
                raise ApiError(ApiErrorCode.INVALID_RESPONSE)
            headers[name] = value
        length = headers.get('content-length')
        transfer = headers.get('transfer-encoding')
        if (transfer not in (None, 'chunked') or transfer and length is not None
                or length is not None and not re.fullmatch(r'[0-9]{1,10}', length)):
            raise ApiError(ApiErrorCode.INVALID_RESPONSE)
        if length is not None and int(length) > limit:
            raise ApiError(ApiErrorCode.RESPONSE_TOO_LARGE)
        if headers.get('content-encoding', 'identity') != 'identity':
            raise ApiError(ApiErrorCode.INVALID_RESPONSE)
        self.headers = MappingProxyType(headers)
        self._expected_length = int(length) if length is not None else None

    def read(self, max_bytes, *, timeout):
        error = None
        try:
            if self._closed or type(max_bytes) is not int or not 1 <= max_bytes <= 65536:
                raise ApiError(ApiErrorCode.INVALID_RESPONSE)
            if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
                raise ApiError(ApiErrorCode.TIMEOUT)
            _remaining(self._guard.deadline)
            if self._response.isclosed():
                if self._expected_length is not None and self._count != self._expected_length:
                    raise ApiError(ApiErrorCode.INVALID_RESPONSE)
                return b''
            self._sock.settimeout(min(timeout, self._read_timeout,
                                      _remaining(self._guard.deadline)))
            chunk = self._response.read1(min(max_bytes, self._limit - self._count + 1))
            _remaining(self._guard.deadline)
            self._count += len(chunk)
            if self._count > self._limit:
                raise ApiError(ApiErrorCode.RESPONSE_TOO_LARGE)
            if (not chunk and self._expected_length is not None
                    and self._count != self._expected_length):
                raise ApiError(ApiErrorCode.INVALID_RESPONSE)
            return chunk
        except ApiError as exc:
            error = ApiError(exc.code)
        except TimeoutError:
            error = ApiError(ApiErrorCode.TIMEOUT)
        except ssl.SSLError:
            error = ApiError(ApiErrorCode.TLS_ERROR)
        except Exception:
            error = ApiError(ApiErrorCode.TRANSPORT_ERROR)
        if self._guard.expired:
            error = ApiError(ApiErrorCode.TIMEOUT)
        self.close()
        raise error

    def close(self):
        if not self._closed:
            self._closed = True
            try:
                response_closed = _close_quietly(self._response)
            finally:
                try:
                    connection_closed = _close_quietly(self._connection)
                finally:
                    sockets_closed = self._guard.close()
                    self._release()
            if not (response_closed and connection_closed and sockets_closed):
                raise ApiError(ApiErrorCode.TRANSPORT_ERROR)


def checked_request_headers(request, *, auth=False, has_body=False):
    """Shared TLS/header checks; route, body and effect permissions remain in each adapter."""
    if type(request) not in (GetRequest, PostRequest):
        raise ApiError(ApiErrorCode.ACCESS_DENIED)
    if (request.follow_redirects is not False or request.retries != 0
            or request.trust_environment is not False):
        raise ApiError(ApiErrorCode.ACCESS_DENIED)
    for value in (request.connect_timeout, request.read_timeout, request.deadline):
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise ApiError(ApiErrorCode.TIMEOUT)
    context = request.tls_context
    if (not isinstance(context, ssl.SSLContext) or context.verify_mode != ssl.CERT_REQUIRED
            or context.check_hostname is not True
            or context.minimum_version < ssl.TLSVersion.TLSv1_2
            or context.keylog_filename is not None):
        raise ApiError(ApiErrorCode.TLS_ERROR)
    headers = dict(request.headers)
    expected = {'Accept', 'Accept-Encoding'}
    if auth or has_body:
        expected |= {'Content-Type', 'Content-Length'}
    if not auth:
        expected.add('Authorization')
    if (headers.keys() != expected or headers['Accept'] != 'application/json'
            or headers['Accept-Encoding'] != 'identity'):
        raise ApiError(ApiErrorCode.ACCESS_DENIED)
    if not auth:
        value = headers['Authorization']
        if not isinstance(value, str) or not value.startswith('Bearer '):
            raise ApiError(ApiErrorCode.AUTHENTICATION)
        BearerToken(value[7:])
    return headers


class ReadOnlyHTTPSTransport:
    network_enabled = True

    def __init__(self, policy: ReadOnlyPolicy | GatewayDiagnosticPolicy | GatewayLoginPolicy
                 | TestTargetReadPolicy | SingleTestReadPolicy | GatewayTreeReadPolicy, *,
                 confirmed: bool = False):
        if (type(policy) not in (ReadOnlyPolicy, GatewayDiagnosticPolicy, GatewayLoginPolicy,
                                TestTargetReadPolicy, SingleTestReadPolicy, GatewayTreeReadPolicy)
                or type(confirmed) is not bool):
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        self._policy = policy
        self._confirmed = confirmed
        self._dns = _DNS()
        self._lock = threading.Lock()
        self._requests = 0
        self._target_routes_used = set()

    @property
    def policy(self) -> (ReadOnlyPolicy | GatewayDiagnosticPolicy | GatewayLoginPolicy
                         | TestTargetReadPolicy | SingleTestReadPolicy | GatewayTreeReadPolicy):
        return self._policy

    def _validate(self, request):
        if not self._confirmed:
            raise ApiError(ApiErrorCode.NETWORK_DISABLED)
        if type(request) not in (GetRequest, PostRequest):
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        host, path, auth = self.policy.authorize(request.method, request.url)
        headers = checked_request_headers(request, auth=auth)
        if not auth:
            value = headers['Authorization']
            if not isinstance(value, str) or not value.startswith('Bearer '):
                raise ApiError(ApiErrorCode.AUTHENTICATION)
            BearerToken(value[7:])
            return host, path, None, headers
        if (type(request.body) is not JsonBody or headers['Content-Type'] != 'application/json'
                or not 1 <= request.body.content_length <= 32768
                or headers['Content-Length'] != str(request.body.content_length)):
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        data = bytearray()
        for chunk in request.body.iter_chunks():
            if type(chunk) is not bytes or len(data) + len(chunk) > 32768:
                raise ApiError(ApiErrorCode.ACCESS_DENIED)
            data.extend(chunk)
        body = bytes(data)
        if len(body) != request.body.content_length:
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        value = decode_payload(body)
        fields = {'refresh'} if path.endswith('/refresh/') else {'username', 'password'}
        if (not isinstance(value, dict) or value.keys() != fields
                or any(not isinstance(v, str) or not 1 <= len(v) <= 4096 for v in value.values())):
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        return host, path, body, headers

    def open(self, request):
        """Validate even direct calls; do not rely on SarexClient/CLI write guards."""
        acquired = self._lock.acquire(blocking=False)
        if not acquired:
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        connection = guard = response = None
        handed_off = attempted = False
        error = None
        try:
            host, path, body, headers = self._validate(request)
            if self._requests >= self.policy.max_requests:
                raise ApiError(ApiErrorCode.ACCESS_DENIED)
            if type(self.policy) in (TestTargetReadPolicy, SingleTestReadPolicy):
                if path in self._target_routes_used:
                    raise ApiError(ApiErrorCode.ACCESS_DENIED)
                self._target_routes_used.add(path)  # Consume before DNS, including failed attempts.
            self._requests += 1
            now = time.monotonic()
            deadline = min(request.deadline, now + self.policy.timeouts.total)
            connect_deadline = min(deadline, now + self.policy.timeouts.connect,
                                   now + request.connect_timeout)
            _remaining(connect_deadline)
            # The real adapter owns its trust store; a caller cannot inject alternate CAs.
            tls_context = _tls_context()
            family, address = self._dns.resolve(host, connect_deadline)
            guard = _Deadline(deadline)
            raw = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            guard.add(raw)
            raw.settimeout(_remaining(connect_deadline))
            raw.connect(address)  # Already validated numeric address; no second DNS lookup.
            if ipaddress.ip_address(raw.getpeername()[0]) != ipaddress.ip_address(address[0]):
                raise ApiError(ApiErrorCode.ACCESS_DENIED)
            raw.settimeout(_remaining(connect_deadline))
            tls = tls_context.wrap_socket(raw, server_hostname=host, do_handshake_on_connect=False)
            guard.add(tls)
            tls.do_handshake()
            _remaining(connect_deadline)
            read_timeout = min(request.read_timeout, self.policy.timeouts.read)
            tls.settimeout(min(read_timeout, _remaining(deadline)))
            connection = http.client.HTTPConnection(host, 443)
            connection.auto_open = 0  # Never let http.client resolve/reconnect on its own.
            connection.set_debuglevel(0)
            connection.response_class = _HTTPResponse
            connection.sock = tls
            headers['Connection'] = 'close'
            attempted = True
            connection.request(request.method, path, body=body, headers=headers)
            response = connection.getresponse()
            _remaining(deadline)
            if 300 <= response.status < 400:
                raise ApiError(ApiErrorCode.REDIRECT_REJECTED, response.status)
            wrapper = _Response(response, connection, tls, guard, self.policy.max_response_bytes,
                                read_timeout, self._lock.release)
            handed_off = True
            return wrapper
        except ApiError as exc:
            error = ApiError(exc.code, exc.status)
        except TimeoutError:
            error = ApiError(ApiErrorCode.TIMEOUT)
        except ssl.SSLError:
            error = ApiError(ApiErrorCode.TLS_ERROR)
        except Exception:
            error = ApiError(ApiErrorCode.TRANSPORT_ERROR)
        finally:
            if isinstance(request, PostRequest) and isinstance(request.body, JsonBody):
                request.body.clear()
            if not handed_off:
                try:
                    _close_quietly(response)
                    _close_quietly(connection)
                finally:
                    if guard is not None:
                        guard.close()
                    self._lock.release()
        if guard is not None and guard.expired:
            error = ApiError(ApiErrorCode.TIMEOUT)
        if (type(self.policy) is GatewayDiagnosticPolicy and response is not None
                and type(response.status) is int and 100 <= response.status <= 599):
            # Preserve a received status even if framing/size validation rejected the body.
            error.status = response.status
        error.outcome_unknown = attempted and request.method == 'POST'
        raise error
