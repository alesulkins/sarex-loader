"""Persistent one-document customer test; never a reset mechanism for old operations."""

import hashlib
import json
import re
from pathlib import Path

from sarex_loader.file_safety import read_snapshot
from sarex_loader.journal import fingerprint
from sarex_loader.safety import ValidationError
from sarex_loader.single_test_scope import TEST_DISK_ID, TEST_PARENT_ID, TEST_PATH_IDS, TEST_ROOT_ID


def state_path():
    return Path.home() / '.sarex-loader-synthetic-test'


def journal_path():
    return state_path() / 'journal'


def manifest():
    try:
        data = json.loads(read_snapshot(state_path() / 'manifest.json', 16384))
        if not isinstance(data, dict) or set(data) != {
                'context', 'operation_key', 'item', 'plan_sha256', 'excel_sha256'}:
            raise ValueError
        return data
    except (ValueError, OSError):
        raise ValidationError('Тестовый план недоступен или повреждён. Сброс запрещён.') from None


def validate_item(item):
    data = manifest()
    expected = data['item']
    if (item != expected or item.get('resolved_folder_id') != TEST_PARENT_ID
            or tuple(item.get('resolved_path_ids', ())) != TEST_PATH_IDS
            or item.get('target_folder_id') != str(TEST_ROOT_ID)
            or item.get('disk_id') != TEST_DISK_ID
            or item.get('status') != 'LOCAL_MATCH'
            or item.get('document_type') != 'pdf' or item.get('file_key') != 'pdf'
            or item.get('customer_test') is not True
            or not re.fullmatch(r'2026-10-05-SAREX-TEST-[0-9]{12}\.pdf',
                                item.get('filename', ''))
            or item.get('filename') != '2026-10-05-SAREX-TEST-' + str(item.get('number')) + '.pdf'
            or item.get('bundle_date') != '2026-10-05T12:00:00+03:00'
            or fingerprint(item) != data['operation_key']):
        raise ValidationError('Тестовый документ или цель вне разрешённого плана.')
    pdf = state_path() / 'input' / 'pdf' / item['filename']
    from sarex_loader.synthetic_pdf import synthetic_pdf_bytes

    raw = read_snapshot(pdf, 8192)
    if raw != synthetic_pdf_bytes() or hashlib.sha256(raw).hexdigest() != item['pdf_sha256']:
        raise ValidationError('Тестовый PDF изменён.')
    return TEST_PARENT_ID, TEST_PATH_IDS


def validate_journal(journal):
    if journal.path != journal_path() or len(journal.checkpoints()) != 1:
        raise ValidationError('Нужен неизменный журнал одного тестового PDF.')
    for key in journal.checkpoints():
        validate_item(journal.operation(key))
        if key != manifest()['operation_key']:
            raise ValidationError('Изменён ключ тестовой операции.')
