"""Customer command: one stable synthetic document, preview first, explicit plan consent."""

import hashlib
import json
import os
import secrets
from datetime import datetime

from openpyxl import Workbook

from sarex_loader import customer_test_scope as scope
from sarex_loader.acceptance_upload import check_duplicates, read_targets
from sarex_loader.audit import HEADERS
from sarex_loader.config import RunConfig, checked_path
from sarex_loader.excel_copy import URLUpdate, make_url_copy
from sarex_loader.file_safety import read_snapshot
from sarex_loader.gateway_tree import gateway_login
from sarex_loader.journal import (
    BATCH_CONFIRMATION_POLICY,
    BATCH_DOCUMENT_STATES,
    Journal,
    fingerprint,
)
from sarex_loader.pipeline import build_plan
from sarex_loader.profile_auth import use_settings
from sarex_loader.reports import _write_bundle
from sarex_loader.safety import ValidationError
from sarex_loader.single_test_scope import TEST_DISK_ID, TEST_PATH_IDS, TEST_ROOT_ID
from sarex_loader.synthetic_pdf import synthetic_pdf_bytes
from sarex_loader.user_settings import require_settings


def config_for(output):
    inputs = scope.state_path() / 'input'
    tree = inputs / 'tree.json'
    return RunConfig(
        command='upload', input_root=inputs, excel='registry.xlsx', pdf_dir='pdf',
        inspection_type='sk', target_folder_id=str(TEST_ROOT_ID),
        journal_dir=scope.journal_path(), output_dir=output, filename_separator='-',
        office_folders={'Synthetic office': '1-ОФ'},
        contractor_folders={'Synthetic company': 'РТ-Инжиниринг'}, inspection_folder='Инспекции',
        folder_prefix=('2026-10-Тест ПО (Автоматизация)', 'ТЕСТ ЗАГРУЗКИ'),
        tree={'source': 'json', 'disk_id': TEST_DISK_ID,
              'exports': [{'path': 'tree.json',
                           'sha256': hashlib.sha256(read_snapshot(tree, 65536)).hexdigest()}]})


def prepare(index):
    root = scope.state_path()
    # A missing journal in an existing state is never treated as a fresh start.
    if root.exists() or root.is_symlink():
        checked_path(root, directory=True)
        data = scope.manifest()
        checked_path(scope.journal_path(), directory=True)
        context, operations, checkpoints = Journal.peek(scope.journal_path())
        if (context != fingerprint(data['context']) or operations != {
                data['operation_key']: data['item']}):
            raise ValidationError('Журнал теста не соответствует плану; сброс запрещён.')
        scope.validate_item(data['item'])
        return data
    ids = set(TEST_PATH_IDS)
    if not ids <= index.documents.keys():
        raise ValidationError('Не подтверждена полная цепочка 99-Тест.')
    checked_path(root.parent, directory=True)
    root.mkdir(mode=0o700)  # Concurrent preparation must fail, never overwrite.
    inputs = root / 'input'
    inputs.mkdir()
    (inputs / 'pdf').mkdir()
    number = str(100000000000 + secrets.randbelow(900000000000))
    filename = '2026-10-05-SAREX-TEST-' + number + '.pdf'
    (inputs / 'pdf' / filename).write_bytes(synthetic_pdf_bytes())
    workbook = Workbook()
    workbook.active.title = 'Тест'
    workbook.active.append(HEADERS)
    workbook.active.append([1, datetime(2026, 10, 5, 13),
                            'Synthetic office', 'Synthetic company', number, None])
    workbook.save(inputs / 'registry.xlsx')
    workbook.close()
    raw = {'documents': [
        {'id': i, 'name': index.documents[i].name, 'is_folder': index.documents[i].is_folder,
         'path': '.'.join(map(str, index.documents[i].path_ids))} for i in sorted(ids)]}
    (inputs / 'tree.json').write_text(json.dumps(raw, ensure_ascii=False), encoding='utf-8')
    report = build_plan(config_for(root / 'unused-output'), check_existing_documents=False)
    if len(report['operations']) != 1 or report['matching']['blocked_registry_types']:
        raise ValidationError('Синтетический PDF не прошёл проверки плана.')
    original, = report['operations'].values()
    item = {**original, 'mode': 'batch-test-v2', 'customer_test': True,
            'confirmation_policy': BATCH_CONFIRMATION_POLICY,
            'document_type': 'pdf', 'file_key': 'pdf', 'bundle_date': '2026-10-05T12:00:00+03:00'}
    key = fingerprint(item)
    context = {'mode': 'customer-synthetic-test-v1', 'operations': {key: item}}
    data = {'context': context, 'operation_key': key, 'item': item,
            'plan_sha256': fingerprint(context), 'excel_sha256': report['registry']['sha256']}
    with (root / 'manifest.json').open('x', encoding='utf-8') as stream:
        json.dump(data, stream, ensure_ascii=False)
        stream.flush()
        os.fsync(stream.fileno())
    scope.validate_item(item)
    with Journal(scope.journal_path(), [inputs]) as journal:
        journal.register(context, {key: item})
    return data


def run(*, expected_plan=None, ask=input):
    settings = require_settings()
    with use_settings(settings), gateway_login() as provider:
        index, evidence = read_targets(provider)
        data = prepare(index)
        key, item = data['operation_key'], data['item']
        output = scope.state_path() / ('result-' + secrets.token_hex(8))
        config = config_for(output)
        report = build_plan(config, check_existing_documents=False)
        snapshot = read_snapshot(config.excel, 1024**2)
        if hashlib.sha256(snapshot).hexdigest() != data['excel_sha256']:
            raise ValidationError('Тестовый Excel изменён.')
        summary = {'plan_sha256': data['plan_sha256'], 'filename': item['filename'],
                   'folder_id': item['resolved_folder_id'], 'root_id': TEST_ROOT_ID,
                   'dry_run': expected_plan is None, 'targets': evidence,
                   'server_completeness': 'UNKNOWN',
                   'exception': 'ONLY_THIS_PINNED_SYNTHETIC_DOCUMENT'}
        with Journal(scope.journal_path(), [config.input_root]) as journal:
            scope.validate_journal(journal)
            allowed = {'PLANNED', 'ATTACHED', *BATCH_DOCUMENT_STATES}
            if journal.checkpoint(key)['state'] not in allowed:
                raise ValidationError('OUTCOME_UNKNOWN: повтор POST запрещён. Журнал сохранён.')
            check_duplicates(index, {key: item}, journal.checkpoints())
            if expected_plan is not None:
                if expected_plan != data['plan_sha256']:
                    raise ValidationError('SHA-256 плана не совпадает. Отправка запрещена.')
                print('Только 99-Тест, папка 7915046. Файл: ' + item['filename'])
                if ask('Разрешить отправку этого тестового PDF? Введите «да»: ').strip() != 'да':
                    raise ValidationError('Отправка отменена. Никаких ресурсных POST не выполнено.')
                fresh, _ = read_targets(provider)
                check_duplicates(fresh, {key: item}, journal.checkpoints())
                from sarex_loader.upload_workflow import _execute_batch

                result = _execute_batch(config, {'max_documents': 1}, report, {key: item},
                                        journal, False, False, provider, customer_test=True)
                summary.update(result)
                updates = [URLUpdate(item['sheet'], item['row'], item['row_id'], item['number'],
                                     f'https://lk.sarex.io/documentations/{identifier}')
                           for identifier in result['urls'].values()]
                workbook = make_url_copy(snapshot, data['excel_sha256'], updates,
                                         approved_document_ids=tuple(result['urls'].values()))
                payloads = {'registry.test.xlsx': workbook}
            else:
                payloads = {}
            summary['checkpoints'] = journal.checkpoints()
            payloads['result.json'] = json.dumps(summary, ensure_ascii=False, indent=2).encode()
            _write_bundle(output, payloads, [config.input_root, scope.journal_path()])
    print('Тестовый PDF: ' + item['filename'])
    print('План SHA-256: ' + data['plan_sha256'])
    print('Результаты: ' + str(output))
    if expected_plan is None:
        print('Только GET. Для отдельного подтверждения: -test-pdf --send ' + data['plan_sha256'])
    else:
        print(f"Загружено: {summary['uploaded']}; ранее подтверждено: "
              f"{summary['already_confirmed']}; ошибок: {len(summary['errors'])}.")
    return summary


def command(argv):
    if argv and (len(argv) != 2 or argv[0] != '--send'):
        raise ValidationError('Команда: -test-pdf или -test-pdf --send SHA256.')
    from sarex_loader.api_models import ApiError

    try:
        result = run(expected_plan=argv[1] if argv else None)
    except ApiError as exc:
        raise ValidationError(
            'Тест остановлен: ошибка API ' + exc.code.value
            + '. Не сбрасывайте журнал и не повторяйте неопределённый POST.') from None
    return 3 if result.get('stopped') else 0
