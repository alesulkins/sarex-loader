"""Legacy preparation entrypoint; never silently upgrade its confirmation to real writes.

The reviewed fixed-scope test now lives in sarex_loader.single_test, with a different
config, durable journal and an interactive confirmation. This entrypoint stays offline.
"""

import json
import sys
import tomllib
import uuid

from sarex_loader.api_models import valid_id
from sarex_loader.cli import SafeParser
from sarex_loader.config import local_path
from sarex_loader.file_safety import read_snapshot
from sarex_loader.safety import ValidationError
from sarex_loader.test_target_policy import TEST_PARENT_ID, TEST_ROOT_ID

BLOCKERS = (
    'LEGACY_ENTRYPOINT_DISABLED_USE_SINGLE_TEST',
)


def prepare_single_upload(path, *, confirm_live_single=False):
    try:
        data = tomllib.loads(read_snapshot(local_path(path).absolute(), 8192).decode('utf-8'))
        if (set(data) != {'mode', 'disk_id', 'parent_id', 'synthetic_pdf'}
                or data['mode'] != 'single-live-synthetic'
                or type(confirm_live_single) is not bool
                or type(data['disk_id']) is not str
                or str(uuid.UUID(data['disk_id'])) != data['disk_id']
                or uuid.UUID(data['disk_id']).int == 0
                or not valid_id(data['parent_id']) or data['parent_id'] != TEST_PARENT_ID
                or data['synthetic_pdf'] != 'GENERATED_IN_MEMORY_ONLY'):
            raise ValueError
    except Exception:
        raise ValidationError('Некорректная конфигурация single-live-synthetic.') from None
    # No PDF path/directory/Excel, credentials, endpoint, transport or arbitrary request
    # accepted. A future reviewed implementation must generate its single PDF internally.
    if confirm_live_single:
        raise ValidationError('LIVE_UPLOAD_BLOCKED: прежняя команда отключена; см. single_test.')
    return {'mode': 'SINGLE_LIVE_PREVIEW', 'network_enabled': False,
            'parent_id': TEST_PARENT_ID, 'allowed_root_id': TEST_ROOT_ID,
            'server_checks_performed': False, 'write_contract_confirmed': False,
            'read_only_check_command': 'python -B -m sarex_loader.test_target_check',
            'write_enabled': False, 'max_documents': 1, 'synthetic_pdf_only': True,
            'status': 'BLOCKED', 'blockers': list(BLOCKERS)}


def main(argv=None):
    parser = SafeParser(description='Подготовка одной синтетической загрузки; пока заблокирована.')
    parser.add_argument('--config', required=True)
    parser.add_argument('--confirm-live-single', action='store_true')
    try:
        args = parser.parse_args(argv)
        print(json.dumps(prepare_single_upload(args.config,
                                             confirm_live_single=args.confirm_live_single)))
        return 3
    except ValidationError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    except Exception:
        print('LIVE_UPLOAD_PREPARATION_FAILED: значения скрыты.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
