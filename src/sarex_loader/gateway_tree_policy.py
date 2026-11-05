"""One exact metadata GET on the disk verified by the bounded live probe."""

from dataclasses import dataclass, field

from sarex_loader.api_client import Timeouts
from sarex_loader.api_models import ApiError, ApiErrorCode, valid_id
from sarex_loader.gateway_diagnostic_policy import GATEWAY_TEST_DISK_ID
from sarex_loader.safety import ValidationError


@dataclass(frozen=True, repr=False)
class GatewayTreeReadPolicy:
    disk_id: str
    folder_id: int
    max_response_bytes: int = 8 * 1024**2
    timeouts: Timeouts = field(default_factory=Timeouts)
    max_requests: int = field(default=1, init=False)

    def __post_init__(self):
        if (self.disk_id != GATEWAY_TEST_DISK_ID or not valid_id(self.folder_id)
                or type(self.timeouts) is not Timeouts
                or type(self.max_response_bytes) is not int
                or not 1 <= self.max_response_bytes <= 8 * 1024**2):
            raise ValidationError('TREE_GATEWAY_SCOPE_INVALID')

    @property
    def path(self):
        return f'/gateway/api/v1/disks/{self.disk_id}/documents?child_id={self.folder_id}'

    @property
    def url(self):
        return 'https://api.sarex.io' + self.path

    def authorize(self, method, url):
        if method != 'GET':
            raise ApiError(ApiErrorCode.WRITES_DISABLED)
        if type(url) is not str or url != self.url:
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        return 'api.sarex.io', self.path, False
