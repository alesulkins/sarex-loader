"""Safe preview only until the real Gateway route and Identity contract are confirmed."""

import json
import sys

from sarex_loader.api_models import ApiError, ApiErrorCode
from sarex_loader.cli import SafeParser
from sarex_loader.gateway_summary import GATEWAY_DISK_ID, GATEWAY_FOLDER_ID, GATEWAY_TARGET_ID
from sarex_loader.safety import ValidationError


def main(argv=None):
    parser = SafeParser(description='Gateway: preview; реальный маршрут/Identity не подтверждены.')
    parser.add_argument('--confirm-gateway-read-only', action='store_true')
    try:
        args = parser.parse_args(argv)
        if args.confirm_gateway_read_only:
            # No prompt, auth, token acquisition, transport construction or DNS is allowed.
            raise ApiError(ApiErrorCode.UNSUPPORTED_OPERATION)
        print(json.dumps({
            'mode': 'GATEWAY_READ_ONLY_PREVIEW', 'network_started': False,
            'disk_id': GATEWAY_DISK_ID, 'folder_id': GATEWAY_FOLDER_ID,
            'target_id': GATEWAY_TARGET_ID, 'real_request_available': False,
            'blockers': ['UNCONFIRMED_GATEWAY_URL', 'UNCONFIRMED_IDENTITY_AUTH_CONTRACT'],
        }))
        return 0
    except (ApiError, ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
