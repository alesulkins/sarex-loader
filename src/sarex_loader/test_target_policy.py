"""Fixed read scope for the customer-authorized test branch. No resource write routes."""

from dataclasses import dataclass, field

from sarex_loader.api_client import Timeouts
from sarex_loader.api_models import ApiError, ApiErrorCode
from sarex_loader.read_only_policy import DOCUMENTATION_BASE
from sarex_loader.safety import ValidationError

TEST_ROOT_ID = 2093037
TEST_PARENT_ID = 7915046
TARGET_READ_ROUTES = (
    f'/v1/documents/{TEST_PARENT_ID}',
    f'/v1/documents/{TEST_ROOT_ID}',
    f'/v1/documents/{TEST_PARENT_ID}/ancestors',
)


@dataclass(frozen=True, repr=False)
class TestTargetReadPolicy:
    __test__ = False  # This is a runtime policy, not a pytest test class.
    timeouts: Timeouts = field(default_factory=Timeouts)
    max_response_bytes: int = 1024**2
    max_requests: int = field(default=3, init=False)

    def __post_init__(self):
        if (type(self.timeouts) is not Timeouts or type(self.max_response_bytes) is not int
                or not 1 <= self.max_response_bytes <= 8 * 1024**2):
            raise ValidationError('Некорректные лимиты проверки тестовой папки.')

    def authorize(self, method, url):
        if type(method) is not str or type(url) is not str:
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        if method != 'GET':
            raise ApiError(ApiErrorCode.WRITES_DISABLED)
        if url not in {DOCUMENTATION_BASE + route for route in TARGET_READ_ROUTES}:
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        return 'api.sarex.io', url[len('https://api.sarex.io'):], False


@dataclass(frozen=True, repr=False)
class SingleTestReadPolicy(TestTargetReadPolicy):
    """Exactly target/root/types, once each. Not even token POST is allowed here."""

    def authorize(self, method, url):
        if type(method) is not str or type(url) is not str:
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        if method != 'GET':
            raise ApiError(ApiErrorCode.WRITES_DISABLED)
        routes = (TARGET_READ_ROUTES[0], TARGET_READ_ROUTES[1], '/v1/documents/types')
        if url not in {DOCUMENTATION_BASE + route for route in routes}:
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        return 'api.sarex.io', url[len('https://api.sarex.io'):], False
