"""Gateway client restricted to an explicit synthetic two-header mock contract."""

import ssl
import time
from types import MappingProxyType

from sarex_loader.api_client import (
    ApiSettings,
    Timeouts,
    _read_response_body,
    _remaining,
    _status_error,
    _tls_context,
)
from sarex_loader.api_models import ApiError, ApiErrorCode
from sarex_loader.api_transport import BearerToken, GetRequest
from sarex_loader.gateway_mock_transport import MOCK_GATEWAY_URL, GatewayMockTransport
from sarex_loader.gateway_models import (
    MAX_GATEWAY_BYTES,
    GatewayDocuments,
    GatewaySearchDocument,
    parse_gateway_search_documents,
)
from sarex_loader.safety import ValidationError


class GatewayClient:
    def __init__(self, *, transport: GatewayMockTransport | None = None,
                 access_token: BearerToken | None = None,
                 identity_token: BearerToken | None = None,
                 mock_auth_contract_confirmed: bool = False,
                 timeouts: Timeouts | None = None,
                 max_response_bytes: int = MAX_GATEWAY_BYTES):
        if type(mock_auth_contract_confirmed) is not bool:
            raise ValidationError('Нужен явный boolean тестового контракта Gateway.')
        self._settings = ApiSettings('https://gateway.example.invalid',
                                     ('https://gateway.example.invalid',),
                                     timeouts=timeouts if timeouts is not None else Timeouts(),
                                     max_response_bytes=max_response_bytes)
        self._transport = transport
        self._access = access_token
        self._identity = identity_token
        self._mock_confirmed = mock_auth_contract_confirmed

    def get_documents(self) -> GatewayDocuments[GatewaySearchDocument]:
        # This flag simulates a contract in tests. It NEVER authorizes real network access.
        if not self._mock_confirmed:
            raise ApiError(ApiErrorCode.UNSUPPORTED_OPERATION)
        if (type(self._transport) is not GatewayMockTransport
                or self._transport.network_enabled is not False):
            raise ApiError(ApiErrorCode.NETWORK_DISABLED)
        if type(self._access) is not BearerToken or type(self._identity) is not BearerToken:
            raise ApiError(ApiErrorCode.REAUTH_REQUIRED)
        response = None
        error = None
        result = None
        try:
            settings = self._settings
            deadline = time.monotonic() + settings.timeouts.total
            context = _tls_context()
            if (context.verify_mode != ssl.CERT_REQUIRED or context.check_hostname is not True
                    or context.minimum_version < ssl.TLSVersion.TLSv1_2
                    or context.keylog_filename is not None):
                raise ApiError(ApiErrorCode.TLS_ERROR)
            request = GetRequest(
                url=MOCK_GATEWAY_URL,
                headers=MappingProxyType({
                    'Accept': 'application/json', 'Accept-Encoding': 'identity',
                    'Authorization': self._access.header_value(),
                    'Identity': self._identity.header_value(),
                }),
                tls_context=context,
                connect_timeout=min(settings.timeouts.connect, _remaining(deadline)),
                read_timeout=min(settings.timeouts.read, _remaining(deadline)), deadline=deadline,
            )
            response = self._transport.open(request)
            _remaining(deadline)
            failure = _status_error(response.status)
            if failure is not None:
                raise failure
            body = _read_response_body(response, settings.max_response_bytes,
                                       settings.timeouts, deadline)
            result = parse_gateway_search_documents(
                body, max_response_bytes=settings.max_response_bytes)
            _remaining(deadline)
        except ApiError as exc:
            error = ApiError(exc.code, exc.status)
        except TimeoutError:
            error = ApiError(ApiErrorCode.TIMEOUT)
        except ssl.SSLError:
            error = ApiError(ApiErrorCode.TLS_ERROR)
        except Exception:
            error = ApiError(ApiErrorCode.TRANSPORT_ERROR)
        finally:
            if response is not None:
                response.close()
        # Do not retain raw exception contexts, headers, names or simulated transport errors.
        if error is not None:
            raise error
        return result
