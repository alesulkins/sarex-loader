"""Isolated Documentation client. Supplemental POST methods require explicit mock opt-in."""

from __future__ import annotations

import copy
import math
import re
import ssl
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from sarex_loader.api_models import (
    ApiError,
    ApiErrorCode,
    Document,
    JSONValue,
    decode_payload,
    parse_ancestors,
    parse_document,
    valid_id,
)
from sarex_loader.api_transport import (
    BearerToken,
    DisabledTransport,
    GetRequest,
    JsonBody,
    OfflineReadTransport,
    PostRequest,
    ReadResponse,
    RequestBody,
)
from sarex_loader.api_upload_models import (
    Bundle,
    BundleDraft,
    DocumentType,
    parse_bundle,
    parse_types,
    path_id,
)
from sarex_loader.folder_resolver import safe_component
from sarex_loader.safe_logging import Event, make_logger
from sarex_loader.safety import ValidationError

if TYPE_CHECKING:
    from sarex_loader.https_transport import ReadOnlyHTTPSTransport

DOCUMENT_ROUTE = '/v1/documents/{document_id}'
ANCESTORS_ROUTE = '/v1/documents/{document_id}/ancestors'
MAX_RESPONSE_BYTES = 8 * 1024**2


def _url_parts(value: str) -> tuple[str, str]:
    if (not isinstance(value, str) or len(value) > 512 or not value.isascii()
            or any(ord(c) <= 32 or ord(c) == 127 for c in value)
            or any(c in value for c in '\\%?#@')):
        raise ValidationError('Нужен явный безопасный HTTPS base URL без query/credentials.')
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname or ''
        port = parsed.port
    except ValueError:
        raise ValidationError('Некорректный HTTPS origin.') from None
    # No IP literals, localhost, ambiguous numeric hosts, Unicode/IDNA guessing or trailing dots.
    labels = hostname.split('.')
    if (parsed.scheme != 'https' or not parsed.netloc or len(labels) < 2
            or not re.fullmatch(r'[a-z]{2,63}', labels[-1])
            or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in labels)
            or hostname.endswith(('.localhost', '.local'))
            or port is not None and not 1 <= port <= 65535
            or not re.fullmatch(r'(?:/[A-Za-z0-9_-]+)*/?', parsed.path)):
        raise ValidationError('HTTPS origin или префикс API не разрешён локальной политикой.')
    origin = f'https://{hostname}' + (f':{port}' if port not in (None, 443) else '')
    return origin, parsed.path.rstrip('/')


@dataclass(frozen=True)
class Timeouts:
    connect: float = 5.0
    read: float = 10.0
    total: float = 30.0

    def __post_init__(self) -> None:
        for value in (self.connect, self.read, self.total):
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 300:
                raise ValidationError('Таймауты должны быть конечными числами от 0 до 300 секунд.')
        if self.connect > self.total or self.read > self.total:
            raise ValidationError('Таймаут подключения/чтения не может превышать общий.')


@dataclass(frozen=True, repr=False)
class ApiSettings:
    base_url: str
    allowed_origins: tuple[str, ...]
    timeouts: Timeouts = field(default_factory=Timeouts)
    max_response_bytes: int = 1024**2

    def __post_init__(self) -> None:
        if not isinstance(self.timeouts, Timeouts):
            raise ValidationError('Нужны явные валидные настройки таймаутов.')
        if (type(self.max_response_bytes) is not int
                or not 1 <= self.max_response_bytes <= MAX_RESPONSE_BYTES):
            raise ValidationError('Лимит ответа должен быть целым числом от 1 до 8388608.')
        if (not isinstance(self.allowed_origins, tuple)
                or not 1 <= len(self.allowed_origins) <= 16):
            raise ValidationError('Нужен явный ограниченный allowlist HTTPS origins.')
        origins = []
        for entry in self.allowed_origins:
            origin, prefix = _url_parts(entry)
            if prefix:
                raise ValidationError('В allowlist разрешены только origins без пути.')
            origins.append(origin)
        origin, prefix = _url_parts(self.base_url)
        if origin not in origins:
            raise ValidationError('Origin base URL отсутствует в allowlist.')
        object.__setattr__(self, 'base_url', origin + prefix)
        object.__setattr__(self, 'allowed_origins', tuple(origins))


def _remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise ApiError(ApiErrorCode.TIMEOUT)
    return value


def _tls_context() -> ssl.SSLContext:
    # Use system trust and compiled OpenSSL paths, ignoring CA and keylog environment variables.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if sys.platform == 'win32':
        server_auth = ssl.Purpose.SERVER_AUTH.oid
        certificates = b''.join(
            certificate
            for store in ('CA', 'ROOT')
            for certificate, encoding, trust in ssl.enum_certificates(store)
            if encoding == 'x509_asn' and (trust is True or server_auth in trust)
        )
        if certificates:
            context.load_verify_locations(cadata=certificates)
    defaults = ssl.get_default_verify_paths()
    cafile = defaults.openssl_cafile if Path(defaults.openssl_cafile).is_file() else None
    capath = defaults.openssl_capath if Path(defaults.openssl_capath).is_dir() else None
    if cafile is not None or capath is not None:
        context.load_verify_locations(cafile=cafile, capath=capath)
    elif not context.cert_store_stats()['x509_ca']:
        raise ssl.SSLError('Trusted CA installation required.')
    return context


def _status_error(status: int) -> ApiError | None:
    if type(status) is not int or not 100 <= status <= 599:
        return ApiError(ApiErrorCode.INVALID_RESPONSE)
    if status == 200:
        return None
    code = {
        401: ApiErrorCode.AUTHENTICATION, 403: ApiErrorCode.ACCESS_DENIED,
        404: ApiErrorCode.NOT_FOUND, 429: ApiErrorCode.RATE_LIMITED,
    }.get(status, ApiErrorCode.HTTP_ERROR)
    if 300 <= status <= 399:
        code = ApiErrorCode.REDIRECT_REJECTED
    elif status >= 500:
        code = ApiErrorCode.SERVER_ERROR
    return ApiError(code, status)


def _headers(response: ReadResponse, limit: int) -> int | None:
    headers = response.headers
    if not isinstance(headers, Mapping) or len(headers) > 64:
        raise ApiError(ApiErrorCode.INVALID_RESPONSE)
    normalized = {}
    total = 0
    for key, value in headers.items():
        if (not isinstance(key, str) or not isinstance(value, str)
                or not re.fullmatch(r'[A-Za-z0-9-]{1,128}', key)
                or not value.isascii() or any(ord(c) < 32 or ord(c) == 127 for c in value)
                or key.lower() in normalized):
            raise ApiError(ApiErrorCode.INVALID_RESPONSE)
        total += len(key) + len(value)
        if total > 32768:
            raise ApiError(ApiErrorCode.RESPONSE_TOO_LARGE)
        normalized[key.lower()] = value
    if not re.fullmatch(r'application/json(?:\s*;\s*charset="?utf-8"?)?',
                        normalized.get('content-type', ''), re.IGNORECASE):
        raise ApiError(ApiErrorCode.INVALID_RESPONSE)
    if normalized.get('content-encoding', 'identity').lower() != 'identity':
        raise ApiError(ApiErrorCode.INVALID_RESPONSE)
    length = normalized.get('content-length')
    if length is None:
        return None
    if not re.fullmatch(r'[0-9]{1,10}', length):
        raise ApiError(ApiErrorCode.INVALID_RESPONSE)
    if int(length) > limit:
        raise ApiError(ApiErrorCode.RESPONSE_TOO_LARGE)
    return int(length)


def _read_response_body(response: ReadResponse, limit: int,
                        timeouts: Timeouts, deadline: float) -> bytes:
    """Shared bounded JSON-body reader; callers parse only after full framing validation."""
    advertised = _headers(response, limit)
    body = bytearray()
    while True:
        size = min(65536, limit - len(body) + 1)
        chunk = response.read(size, timeout=min(timeouts.read, _remaining(deadline)))
        _remaining(deadline)
        if type(chunk) is not bytes or len(chunk) > size:
            raise ApiError(ApiErrorCode.INVALID_RESPONSE)
        if not chunk:
            break
        body.extend(chunk)
        if len(body) > limit:
            raise ApiError(ApiErrorCode.RESPONSE_TOO_LARGE)
    if advertised is not None and len(body) != advertised:
        raise ApiError(ApiErrorCode.INVALID_RESPONSE)
    return bytes(body)


class SarexClient:
    def __init__(self, settings: ApiSettings, token: BearerToken | None = None, *,
                 transport: OfflineReadTransport | ReadOnlyHTTPSTransport | None = None,
                 token_provider: Callable[[], BearerToken] | None = None,
                 mock_writes_enabled: bool = False,
                 read_only_network_enabled: bool = False,
                 single_test_network_enabled: bool = False,
                 folder_network_enabled: bool = False,
                 diagnostics_enabled: bool = False) -> None:
        if (not isinstance(settings, ApiSettings)
                or token is not None and not isinstance(token, BearerToken)):
            raise ValidationError('Нужны ApiSettings и явно переданный BearerToken.')
        if (type(mock_writes_enabled) is not bool or type(read_only_network_enabled) is not bool
                or type(diagnostics_enabled) is not bool
                or type(single_test_network_enabled) is not bool
                or type(folder_network_enabled) is not bool
                or folder_network_enabled and (single_test_network_enabled
                                                or read_only_network_enabled or mock_writes_enabled)
                or single_test_network_enabled and (
                    read_only_network_enabled or mock_writes_enabled)
                or token is not None and token_provider is not None):
            raise ValidationError('Нужен один источник токена и явный boolean mock-write режим.')
        self._settings = settings
        self._token = token
        self._token_provider = token_provider
        self._mock_writes_enabled = mock_writes_enabled
        self._read_only_network_enabled = read_only_network_enabled
        self._single_test_network_enabled = single_test_network_enabled
        self._folder_network_enabled = folder_network_enabled
        self._diagnostics_enabled = diagnostics_enabled
        self._response_diagnostic = {}
        self._transport = transport if transport is not None else DisabledTransport()
        self._logger = make_logger(sys.stderr)

    @property
    def response_diagnostic(self) -> dict:
        """Opt-in, bounded structural metadata only. No response/header/body values retained."""
        return copy.deepcopy(self._response_diagnostic)

    def get_document(self, document_id: int) -> Document:
        """GET Document without extend; bundle/bundles semantics remain unverified."""
        value = self._read(DOCUMENT_ROUTE, document_id)
        document = parse_document(value)
        if document.id != document_id:
            if self._diagnostics_enabled:
                self._response_diagnostic['reason'] = 'REQUESTED_ID_MISMATCH'
            raise ApiError(ApiErrorCode.INVALID_RESPONSE)
        return document

    def get_ancestors(self, document_id: int) -> tuple[Document, ...]:
        """GET array of Document; no automatic recursion or assertion about ancestry order."""
        return parse_ancestors(self._read(ANCESTORS_ROUTE, document_id))

    def _read(self, route: str, document_id: int) -> JSONValue:
        if route not in (DOCUMENT_ROUTE, ANCESTORS_ROUTE) or not valid_id(document_id):
            raise ValidationError('Разрешены только два GET-маршрута с положительным int64 ID.')
        return self._exchange('GET', route.format(document_id=document_id))

    def get_document_types(self) -> tuple[DocumentType, ...]:
        return parse_types(self._exchange('GET', '/v1/documents/types'))

    def create_bundle(self, draft: BundleDraft) -> Bundle:
        value = self._exchange('POST', '/v1/bundles', JsonBody(draft.payload()))
        return self._bundle_result(value)

    def upload_single(self, bundle_id: str, key: str, body: RequestBody) -> None:
        # Only the validated single-use file encoder is accepted, never arbitrary form fields.
        from sarex_loader.multipart import MultipartPDF
        from sarex_loader.synthetic_pdf import SyntheticPDF

        if not isinstance(body, MultipartPDF) and type(body) is not SyntheticPDF:
            raise ValidationError('Нужен подготовленный поток MultipartPDF.')
        route = f'/v1/bundles/{path_id(bundle_id)}/{path_id(key)}/upload_single'
        try:
            self._exchange('POST', route, body, json_response=False)
        finally:
            body.close()

    def upload_finish(self, bundle_id: str) -> Bundle:
        value = self._exchange('POST', f'/v1/bundles/{path_id(bundle_id)}/upload_finish')
        bundle = self._bundle_result(value, bundle_id)
        if bundle.upload_status != 'uploaded':
            raise ApiError(ApiErrorCode.INVALID_RESPONSE, outcome_unknown=True)
        return bundle

    def create_document(self, *, disk_id: str, parent_id: int, name: str,
                        bundle_id: str) -> Document:
        if not valid_id(parent_id) or not safe_component(name):
            raise ValidationError('Нужны явная целевая папка и безопасное имя документа.')
        payload = {'disk_id': path_id(disk_id), 'parent_id': parent_id, 'name': name,
                   'is_folder': False, 'bundle_id': path_id(bundle_id)}
        value = self._exchange('POST', '/v1/documents', JsonBody(payload))
        try:
            result = parse_document(value)
            if (result.is_folder or result.name != name
                    or result.disk_id is not None and result.disk_id != disk_id):
                raise ApiError(ApiErrorCode.INVALID_RESPONSE)
        except ApiError:
            raise ApiError(ApiErrorCode.INVALID_RESPONSE, outcome_unknown=True) from None
        return result

    def create_month_folder(self, *, disk_id: str, parent_id: int, name: str) -> Document:
        """Swagger CreateDocumentRequest; guarded month-only workflow.

        The caller must establish completeness, exact parent and naming beforehand.
        Existing transport write/consent gates still apply. No POST retry.
        """
        from sarex_loader.folder_resolver import calendar_month

        if not valid_id(parent_id) or not safe_component(name) or calendar_month(name) is None:
            raise ValidationError('Нужны точный родитель и проверенное название месячной папки.')
        value = self._exchange('POST', '/v1/documents', JsonBody({
            'disk_id': path_id(disk_id), 'parent_id': parent_id, 'name': name, 'is_folder': True}))
        try:
            result = parse_document(value)
            if (not result.is_folder or result.name != name or result.disk_id != disk_id
                    or not result.path or not result.path.endswith(f'.{parent_id}.{result.id}')):
                raise ApiError(ApiErrorCode.INVALID_RESPONSE)
        except ApiError:
            raise ApiError(ApiErrorCode.OUTCOME_UNKNOWN, outcome_unknown=True) from None
        return result

    def add_bundle(self, document_id: int, bundle_id: str) -> Bundle:
        if not valid_id(document_id):
            raise ValidationError('Нужен положительный int64 ID существующего документа.')
        value = self._exchange('POST', f'/v1/documents/{document_id}/add_bundle',
                               JsonBody({'bundle_id': path_id(bundle_id)}))
        result = self._bundle_result(value, bundle_id)
        # Null/missing means no confirmed association, never successful add_bundle.
        if result.document_id != document_id:
            raise ApiError(ApiErrorCode.INVALID_RESPONSE, outcome_unknown=True)
        return result

    @staticmethod
    def _bundle_result(value: JSONValue, expected_id: str | None = None) -> Bundle:
        try:
            result = parse_bundle(value)
            if expected_id is not None and result.id != expected_id:
                raise ApiError(ApiErrorCode.INVALID_RESPONSE)
        except ApiError:
            raise ApiError(ApiErrorCode.INVALID_RESPONSE, outcome_unknown=True) from None
        return result

    def upload_multipart(self) -> None:
        """Chunk upload is unsupported: part numbering/resume/ambiguous routes need confirmation."""
        raise ApiError(ApiErrorCode.UNSUPPORTED_OPERATION)

    def _exchange(self, method: str, route: str, request_body: RequestBody | None = None, *,
                  json_response: bool = True) -> JSONValue:
        self._response_diagnostic = {}
        diagnostic = self._response_diagnostic
        enabled = self._diagnostics_enabled
        if enabled:
            diagnostic.update(http_status=None, phase='REQUEST', json_type='unavailable')
        auth_route = route in ('/token/', '/token/refresh/')
        get_route = re.fullmatch(r'/v1/documents/(?:types|[1-9][0-9]*(?:/ancestors)?)', route)
        post_route = re.fullmatch(
            r'/v1/(?:bundles(?:/[A-Za-z0-9_-]{1,128}/(?:upload_finish|'
            r'[A-Za-z0-9_-]{1,128}/upload_single))?|documents(?:/[1-9][0-9]*/add_bundle)?)',
            route,
        )
        if not (method == 'GET' and get_route or method == 'POST' and (post_route or auth_route)):
            raise ValidationError('Метод или маршрут отсутствует в allowlist.')
        if method == 'POST' and not (
                self._mock_writes_enabled or self._single_test_network_enabled
                or self._folder_network_enabled):
            raise ApiError(ApiErrorCode.WRITES_DISABLED)
        response = None
        error = None
        result = None
        attempted = False
        is_live = False
        single = False
        try:
            if self._transport.network_enabled is not False:
                from sarex_loader.folder_transport import FolderHTTPSTransport
                from sarex_loader.https_transport import ReadOnlyHTTPSTransport
                from sarex_loader.single_test_transport import SingleTestHTTPSTransport

                single = (self._single_test_network_enabled
                          and type(self._transport) is SingleTestHTTPSTransport)
                readonly = (self._read_only_network_enabled
                            and type(self._transport) is ReadOnlyHTTPSTransport)
                folder = (self._folder_network_enabled
                          and type(self._transport) is FolderHTTPSTransport)
                if not (single or readonly or folder):
                    raise ApiError(ApiErrorCode.NETWORK_DISABLED)
                is_live = True
                # Authorize BEFORE token refresh: rejected resource writes have no auth side effect.
                self._transport.policy.authorize(method, self._settings.base_url + route)
            settings = self._settings
            token = None if auth_route else (
                self._token_provider() if self._token_provider is not None else self._token
            )
            if not auth_route and not isinstance(token, BearerToken):
                raise ApiError(ApiErrorCode.REAUTH_REQUIRED)
            deadline = time.monotonic() + settings.timeouts.total
            context = _tls_context()
            if (context.verify_mode != ssl.CERT_REQUIRED or context.check_hostname is not True
                    or context.minimum_version < ssl.TLSVersion.TLSv1_2
                    or context.keylog_filename is not None):
                raise ApiError(ApiErrorCode.TLS_ERROR)
            headers = {'Accept': 'application/json', 'Accept-Encoding': 'identity'}
            if token is not None:
                headers['Authorization'] = token.header_value()
            if request_body is not None:
                headers.update({'Content-Type': request_body.content_type,
                                'Content-Length': str(request_body.content_length)})
            arguments = dict(
                url=settings.base_url + route,
                headers=MappingProxyType(headers),
                tls_context=context, connect_timeout=min(settings.timeouts.connect,
                                                        _remaining(deadline)),
                read_timeout=min(settings.timeouts.read, _remaining(deadline)), deadline=deadline,
            )
            request = (GetRequest(**arguments) if method == 'GET'
                       else PostRequest(**arguments, body=request_body))
            attempted = True
            response = self._transport.open(request)  # One attempt, no redirects or retries.
            if enabled and type(response.status) is int and 100 <= response.status <= 599:
                diagnostic.update(http_status=response.status, phase='HTTP_STATUS')
            _remaining(deadline)
            failure = _status_error(response.status)
            if failure is not None:
                raise failure
            if request_body is not None and not request_body.complete:
                raise ApiError(ApiErrorCode.INVALID_RESPONSE)
            if json_response:
                if enabled:
                    diagnostic['phase'] = 'BODY_AND_HEADERS'
                raw = _read_response_body(
                    response, settings.max_response_bytes, settings.timeouts, deadline)
                if enabled:
                    diagnostic['phase'] = 'JSON_DECODE'
                result = decode_payload(raw)
                raw = b''
                if enabled:
                    from sarex_loader.response_shape import shape, validation_issue

                    kind = ('token' if route == '/token/' else
                            'refresh' if route == '/token/refresh/' else
                            'types' if route == '/v1/documents/types' else
                            'bundle' if route == '/v1/bundles'
                            or route.endswith(('/upload_finish', '/add_bundle')) else
                            'ancestors' if route.endswith('/ancestors') else
                            'document' if route == '/v1/documents'
                            or re.fullmatch(r'/v1/documents/[1-9][0-9]*', route)
                            else 'other')
                    diagnostic.update(shape(result, kind))
                    diagnostic['phase'] = 'MODEL'
                    diagnostic.update(validation_issue(result, kind) or {'reason': 'OK'})
                _remaining(deadline)
        except ApiError as exc:
            error = ApiError(exc.code, exc.status, outcome_unknown=exc.outcome_unknown)
        except TimeoutError:
            error = ApiError(ApiErrorCode.TIMEOUT)
        except ssl.SSLError:
            error = ApiError(ApiErrorCode.TLS_ERROR)
        except Exception:
            error = ApiError(ApiErrorCode.TRANSPORT_ERROR)
        finally:
            if isinstance(request_body, JsonBody):
                request_body.clear()
            if response is not None:
                try:
                    response.close()
                except Exception:
                    if error is None:
                        error = ApiError(ApiErrorCode.TRANSPORT_ERROR)
        # Raise outside the exception handler: no raw exception context/token is retained.
        if enabled and single and attempted:
            diagnostic.update(self._transport.response_diagnostic)
        if error is not None:
            if enabled:
                if diagnostic['http_status'] is None:
                    diagnostic['http_status'] = error.status
                if diagnostic.get('reason') in (None, 'OK'):
                    diagnostic.update(reason=error.code.value)
            error.outcome_unknown |= method == 'POST' and attempted
            self._logger.warning(Event.API_ERROR.value)
            raise error
        if is_live and self._folder_network_enabled and method == 'POST':
            event = Event.API_FOLDER_RESPONSE
        elif is_live and self._single_test_network_enabled and method == 'POST':
            event = Event.API_SINGLE_TEST_RESPONSE
        else:
            event = Event.API_READ_RESPONSE if is_live else Event.API_RESPONSE
        self._logger.info(event.value)
        return result
