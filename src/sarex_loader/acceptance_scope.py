"""One reviewed two-document acceptance manifest; never a production write scope."""

import hashlib
import json
from pathlib import Path

from sarex_loader.file_safety import read_snapshot
from sarex_loader.safety import ValidationError
from sarex_loader.single_test_scope import TEST_DISK_ID, TEST_PATH_IDS, TEST_ROOT_ID

MANIFEST_SHA256 = '9e834f29604dbc9e067e765c7746b9547f2804e88850d9d973226d70f41dbfe9'
TARGET_PATHS = {7915046: TEST_PATH_IDS, 7915045: (*TEST_PATH_IDS[:-1], 7915045)}


def workspace():
    return Path(__file__).resolve().parents[2]


def artifact_path():
    return workspace() / 'outputs' / 'test-upload-20261105'


def journal_path():
    # Never a user-selectable ledger or a replacement for historical UNKNOWN.
    return workspace() / '.two-folder-acceptance-journal'


def manifest():
    raw = read_snapshot(artifact_path() / 'manifest.json', 8192)
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ValidationError('Тестовый манифест изменён; загрузка запрещена.')
    return json.loads(raw)


def validate_item(item):
    approved = manifest()
    allowed = {f['filename']: f for f in approved['files']}
    f = allowed.get(item.get('filename'))
    if (f is None or item.get('resolved_folder_id') != f['parent_id']
            or tuple(item.get('resolved_path_ids', ())) != TARGET_PATHS[f['parent_id']]
            or item.get('disk_id') != TEST_DISK_ID
            or item.get('target_folder_id') != str(TEST_ROOT_ID)
            or item.get('pdf_sha256') != f['sha256'] or item.get('number') != f['number']
            or item.get('bundle_date') != f['date']
            or item.get('row') != f['row'] or item.get('sheet') != 'Тест'
            or item.get('acceptance_manifest_sha256') != MANIFEST_SHA256
            or item.get('status') != 'LOCAL_MATCH'
            or item.get('document_type') != 'pdf' or item.get('file_key') != 'pdf'):
        raise ValidationError('Тестовая операция вне allowlist двух новых синтетических PDF.')
    return f['parent_id'], TARGET_PATHS[f['parent_id']]
