"""User-supplied exact Gateway route, for one access-only hypothesis test."""

from dataclasses import dataclass, field

from sarex_loader.api_client import Timeouts
from sarex_loader.api_models import ApiError, ApiErrorCode
from sarex_loader.gateway_models import HARD_MAX_GATEWAY_BYTES, MAX_GATEWAY_BYTES
from sarex_loader.safety import ValidationError

GATEWAY_DIAGNOSTIC_PATH = (
    '/gateway/api/v1/disks/25cb6f03-454d-4bc6-aeb6-2808c3a2b68b/documents?child_id=6272634&'
)
GATEWAY_DIAGNOSTIC_URL = 'https://api.sarex.io' + GATEWAY_DIAGNOSTIC_PATH
GATEWAY_LOGIN_URL = 'https://lk.sarex.io/api/token/'
GATEWAY_TEST_DISK_ID = '25cbff03-454d-4b6c-aeb6-2808c3a2b68b'
GATEWAY_TEST_FOLDER_ID = 7915046
GATEWAY_TEST_TARGET_ID = 7978396
GATEWAY_TEST_PATH = (
    f'/gateway/api/v1/disks/{GATEWAY_TEST_DISK_ID}/documents?child_id={GATEWAY_TEST_FOLDER_ID}'
)


@dataclass(frozen=True, repr=False)
class GatewayDiagnosticPolicy:
    timeouts: Timeouts = field(default_factory=Timeouts)
    max_response_bytes: int = MAX_GATEWAY_BYTES
    max_requests: int = field(default=1, init=False)
    test_scope: bool = False

    def __post_init__(self):
        if (type(self.test_scope) is not bool or type(self.timeouts) is not Timeouts
                or type(self.max_response_bytes) is not int
                or not 1 <= self.max_response_bytes <= HARD_MAX_GATEWAY_BYTES):
            raise ValidationError('Некорректные лимиты диагностического запроса Gateway.')

    @property
    def path(self):
        return GATEWAY_TEST_PATH if self.test_scope else GATEWAY_DIAGNOSTIC_PATH

    @property
    def url(self):
        return 'https://api.sarex.io' + self.path

    def authorize(self, method: str, url: str) -> tuple[str, str, bool]:
        if type(method) is not str or type(url) is not str:
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        if method != 'GET':
            raise ApiError(ApiErrorCode.WRITES_DISABLED)
        if url != self.url:
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        # Exact comparison: no URL normalization, optional query or auth POST exceptions.
        return 'api.sarex.io', self.path, False


@dataclass(frozen=True, repr=False)
class GatewayLoginPolicy(GatewayDiagnosticPolicy):
    """Separate one-shot transport scope: token issuance only, never refresh or a GET."""

    def authorize(self, method: str, url: str) -> tuple[str, str, bool]:
        if type(method) is not str or type(url) is not str:
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        if method == 'POST' and url == GATEWAY_LOGIN_URL:
            return 'lk.sarex.io', '/api/token/', True
        code = ApiErrorCode.WRITES_DISABLED if method != 'GET' else ApiErrorCode.ACCESS_DENIED
        raise ApiError(code)
