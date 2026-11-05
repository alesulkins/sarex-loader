"""One access-only Gateway GET; hypothesis, never a discovery or authentication fallback."""

import getpass
import json
import ssl
import sys
import time
import warnings
from types import MappingProxyType
from typing import TypedDict

from sarex_loader.api_client import (
    ApiSettings,
    _read_response_body,
    _remaining,
    _status_error,
    _tls_context,
)
from sarex_loader.api_models import ApiError, ApiErrorCode
from sarex_loader.api_transport import BearerToken, GetRequest
from sarex_loader.auth import AuthSession
from sarex_loader.cli import SafeParser
from sarex_loader.gateway_diagnostic_metadata import safe_response_metadata
from sarex_loader.gateway_diagnostic_policy import (
    GATEWAY_LOGIN_URL,
    GATEWAY_TEST_DISK_ID,
    GATEWAY_TEST_FOLDER_ID,
    GATEWAY_TEST_TARGET_ID,
    GatewayDiagnosticPolicy,
    GatewayLoginPolicy,
)
from sarex_loader.gateway_models import MAX_GATEWAY_BYTES, parse_gateway_search_documents
from sarex_loader.gateway_summary import (
    GATEWAY_DISK_ID,
    GATEWAY_FOLDER_ID,
    GATEWAY_TARGET_ID,
    summarize_gateway,
)
from sarex_loader.https_transport import ReadOnlyHTTPSTransport
from sarex_loader.safety import ValidationError

CONFIRMATION = 'GATEWAY LOGIN AND GET 6272634'


class DiagnosticResult(TypedDict):
    http_status: int | None
    content_type: str | None
    request_id: str | None
    request_id_header: str | None
    documents_count: int | None
    target_id: int
    target_found: bool | None
    target_relation: str | None
    error: str | None
    server_completeness_verified: bool
    access_only_is_hypothesis: bool


class GatewayAccessDiagnostic:
    def __init__(self, transport: ReadOnlyHTTPSTransport | None = None, *, confirmed: bool = False):
        if type(confirmed) is not bool:
            raise ValidationError('Нужно явное boolean подтверждение диагностики.')
        self._transport = transport
        self._confirmed = confirmed
        self.documents = ()  # Validated metadata only; never raw headers or credentials.

    def run(self, access: BearerToken) -> DiagnosticResult:
        self.documents = ()
        result: DiagnosticResult = {
            'http_status': None, 'documents_count': None, 'target_id': GATEWAY_TARGET_ID,
            'content_type': None, 'request_id': None, 'request_id_header': None,
            'target_found': None, 'target_relation': None, 'error': None,
            'server_completeness_verified': False, 'access_only_is_hypothesis': True,
        }
        response = None
        try:
            if (not self._confirmed or type(self._transport) is not ReadOnlyHTTPSTransport
                    or type(self._transport.policy) is not GatewayDiagnosticPolicy):
                raise ApiError(ApiErrorCode.NETWORK_DISABLED)
            if type(access) is not BearerToken:
                raise ApiError(ApiErrorCode.REAUTH_REQUIRED)
            policy = self._transport.policy
            folder_id = GATEWAY_TEST_FOLDER_ID if policy.test_scope else GATEWAY_FOLDER_ID
            result['target_id'] = GATEWAY_TEST_TARGET_ID if policy.test_scope else GATEWAY_TARGET_ID
            policy.authorize('GET', policy.url)
            deadline = time.monotonic() + policy.timeouts.total
            request = GetRequest(
                url=policy.url,
                headers=MappingProxyType({
                    'Accept': 'application/json', 'Accept-Encoding': 'identity',
                    'Authorization': access.header_value(),
                }),
                tls_context=_tls_context(),
                connect_timeout=min(policy.timeouts.connect, _remaining(deadline)),
                read_timeout=min(policy.timeouts.read, _remaining(deadline)), deadline=deadline,
            )
            response = self._transport.open(request)
            result['http_status'] = response.status
            result.update(safe_response_metadata(response.headers, access))
            _remaining(deadline)
            failure = _status_error(response.status)
            if failure is not None:
                # Never read a private error body, refresh access, or try Identity/cookies.
                raise failure
            body = _read_response_body(response, policy.max_response_bytes,
                                       policy.timeouts, deadline)
            parsed = parse_gateway_search_documents(
                body, max_response_bytes=policy.max_response_bytes)
            summary = summarize_gateway(parsed, folder_id=folder_id, target_id=result['target_id'])
            _remaining(deadline)
            result['documents_count'] = summary['documents_count']
            result['target_relation'] = summary['target_result']
            result['target_found'] = summary['target_result'] != 'NOT_PRESENT_IN_RESPONSE'
            self.documents = parsed.documents
        except ApiError as exc:
            result['error'] = exc.code.value
            if exc.status is not None:
                result['http_status'] = exc.status
        except TimeoutError:
            result['error'] = ApiErrorCode.TIMEOUT.value
        except ssl.SSLError:
            result['error'] = ApiErrorCode.TLS_ERROR.value
        except Exception:
            result['error'] = ApiErrorCode.TRANSPORT_ERROR.value
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    result['error'] = result['error'] or ApiErrorCode.TRANSPORT_ERROR.value
        if result['error'] is not None:
            self.documents = ()
            result['documents_count'] = result['target_found'] = result['target_relation'] = None
        return result


def main(argv=None):
    parser = SafeParser(
        description='Один Gateway GET с access: проверка гипотезы, preview по умолчанию.')
    parser.add_argument('--confirm-access-only-diagnostic', action='store_true')
    parser.add_argument('--test-scope', action='store_true',
                        help='Подтверждённый диск и папка 7915046; один GET, без повторов.')
    parser.add_argument('--max-response-bytes', type=int, default=MAX_GATEWAY_BYTES)
    username = password = access = auth = None
    try:
        args = parser.parse_args(argv)
        policy = GatewayDiagnosticPolicy(max_response_bytes=args.max_response_bytes,
                                         test_scope=args.test_scope)
        folder_id = GATEWAY_TEST_FOLDER_ID if args.test_scope else GATEWAY_FOLDER_ID
        target_id = GATEWAY_TEST_TARGET_ID if args.test_scope else GATEWAY_TARGET_ID
        confirmation = f'GATEWAY LOGIN AND GET {folder_id}'
        if not args.confirm_access_only_diagnostic:
            print(json.dumps({
                'mode': 'GATEWAY_ACCESS_ONLY_PREVIEW', 'network_started': False,
                'method': 'GET', 'url': policy.url, 'max_requests': 2,
                'auth_method': 'POST', 'auth_url': GATEWAY_LOGIN_URL,
                'max_auth_requests': 1, 'max_gateway_requests': 1,
                'disk_id': GATEWAY_TEST_DISK_ID if args.test_scope else GATEWAY_DISK_ID,
                'folder_id': folder_id,
                'target_id': target_id, 'max_response_bytes': policy.max_response_bytes,
                'auth_headers': ['Authorization'], 'access_only_is_hypothesis': True,
            }))
            return 0
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            raise ValidationError('Диагностика требует интерактивного терминала.')
        print('Только после отдельного разрешения: один POST token и один GET. '
              'Access-only — гипотеза.\n' + GATEWAY_LOGIN_URL + '\n'
              + policy.url + '\nВведите: ' + confirmation, file=sys.stderr)
        if input() != confirmation:
            raise ValidationError('Подтверждение диагностики не получено.')
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            username = getpass.getpass('Login (скрытый ввод): ')
            password = getpass.getpass('Password (скрытый ввод): ')
        login_policy = GatewayLoginPolicy(timeouts=policy.timeouts)
        auth = AuthSession(
            ApiSettings('https://lk.sarex.io/api', ('https://lk.sarex.io',),
                        timeouts=login_policy.timeouts,
                        max_response_bytes=login_policy.max_response_bytes),
            transport=ReadOnlyHTTPSTransport(login_policy, confirmed=True),
            read_only_network_enabled=True,
        )
        try:
            auth.login(username, password)
            access = auth.access_token(allow_refresh=False)
        finally:
            username = password = None
            auth.logout()  # Drop the returned refresh before the Gateway request.
        transport = ReadOnlyHTTPSTransport(policy, confirmed=True)
        result = GatewayAccessDiagnostic(transport, confirmed=True).run(access)
        print(json.dumps(result))
        return 0 if result['error'] is None else 2
    except (ValidationError, ApiError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print('Диагностика прервана; повторов нет.', file=sys.stderr)
        return 130
    except Exception:
        print('Ошибка диагностики; детали скрыты, повторов нет.', file=sys.stderr)
        return 1
    finally:
        username = password = access = None  # Release references, not RAM zeroization.
        if auth is not None:
            auth.logout()


if __name__ == '__main__':
    raise SystemExit(main())
