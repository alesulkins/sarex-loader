"""Explicit, immutable two-PDF acceptance exercise through the current loader.

This module grants no production capability. The narrow exception is evidence of
observed absence for two freshly generated names, not proof of Gateway completeness.
"""

import hashlib
import json
from pathlib import Path

from sarex_loader import acceptance_scope as scope
from sarex_loader.api_client import ApiSettings, SarexClient
from sarex_loader.config import RunConfig
from sarex_loader.excel_copy import URLUpdate, make_url_copy
from sarex_loader.file_safety import read_snapshot
from sarex_loader.folder_resolver import FolderResolver
from sarex_loader.gateway_tree import fetch_gateway, gateway_login
from sarex_loader.gateway_tree_policy import GatewayTreeReadPolicy
from sarex_loader.https_transport import ReadOnlyHTTPSTransport
from sarex_loader.journal import (
    BATCH_CONFIRMATION_POLICY,
    BATCH_DOCUMENT_STATES,
    Journal,
    fingerprint,
)
from sarex_loader.pipeline import _verify_sources, build_plan
from sarex_loader.read_only_policy import DOCUMENTATION_BASE, ReadOnlyPolicy
from sarex_loader.reports import _write_bundle
from sarex_loader.safety import ValidationError
from sarex_loader.single_test_scope import TEST_DISK_ID, TEST_ROOT_ID, verify_target_document
from sarex_loader.tree_source import add_response


def read_targets(token_provider):
    """Five GETs, exactly two target folders plus their test root."""
    client = SarexClient(ApiSettings(DOCUMENTATION_BASE, ('https://api.sarex.io',)),
                         token_provider=token_provider, read_only_network_enabled=True,
                         transport=ReadOnlyHTTPSTransport(
                             ReadOnlyPolicy((TEST_ROOT_ID, *scope.TARGET_PATHS)), confirmed=True))
    root = client.get_document(TEST_ROOT_ID)
    if (root.is_folder is not True or root.name != '99-Тест'
            or root.path != '1600045.2062798.2093037'):
        raise ValidationError('Корень 99-Тест не подтверждён GET.')
    index, evidence = FolderResolver(), {}
    for folder, path in scope.TARGET_PATHS.items():
        target = client.get_document(folder)
        verify_target_document(target, expected_path=path)
        expected = '2026-10' if folder == 7915046 else '2026-09'
        if target.name != expected:
            raise ValidationError('Название тестовой папки изменилось.')
        metadata = {}
        raw = fetch_gateway(GatewayTreeReadPolicy(TEST_DISK_ID, folder), token_provider(),
                            response_metadata=metadata)
        if metadata.get('header_next_page_hint'):
            raise ValidationError('Gateway сообщил о дополнительных страницах.')
        add_response(index, raw, 8 * 1024**2, queried_folder=folder)
        observed = index.documents.get(folder)
        if observed is None or observed.path_ids != path or observed.name != expected:
            raise ValidationError('Gateway и Documentations расходятся по тестовой цели.')
        children = list(index.children.get(folder, {}).values())
        evidence[str(folder)] = {
            'id': folder, 'name': target.name, 'parent_id': path[-2], 'path': target.path,
            'observed_children': [{'id': d.id, 'name': d.name, 'is_folder': d.is_folder,
                                   'path': '.'.join(map(str, d.path_ids))} for d in children],
            'get_verified': True, 'server_completeness': 'UNKNOWN',
        }
    return index, evidence


def prepare(index, output):
    approved = scope.manifest()
    inputs = scope.artifact_path() / 'input'
    snapshot = read_snapshot(inputs / 'registry.xlsx', 1024**2)
    if hashlib.sha256(snapshot).hexdigest() != approved['excel_sha256']:
        raise ValidationError('Синтетический Excel изменён.')
    # Keep only the verified ancestry. Remote PDFs are checked explicitly below;
    # adding our own confirmed documents must not generate new operation keys.
    ids = set().union(*map(set, scope.TARGET_PATHS.values()))
    if not ids <= index.documents.keys():
        raise ValidationError('Gateway не вернул полную цепочку тестовых родителей.')
    raw = json.dumps({'documents': [
        {'id': i, 'name': index.documents[i].name, 'is_folder': index.documents[i].is_folder,
         'path': '.'.join(map(str, index.documents[i].path_ids))} for i in sorted(ids)
    ]}, ensure_ascii=False, sort_keys=True).encode()
    tree_file = inputs / 'verified-test-folders.json'
    if tree_file.exists():
        if read_snapshot(tree_file, 65536) != raw:
            raise ValidationError('Тестовая структура изменилась; требуется новый анализ.')
    else:
        with tree_file.open('xb') as stream:
            stream.write(raw)
    config = RunConfig(
        command='upload', input_root=inputs, excel='registry.xlsx', pdf_dir='pdf',
        inspection_type='sk', target_folder_id=str(TEST_ROOT_ID),
        journal_dir=scope.journal_path(), output_dir=output, filename_separator='-',
        office_folders={'Synthetic office': '1-ОФ'},
        contractor_folders={'Synthetic company': 'РТ-Инжиниринг'}, inspection_folder='Инспекции',
        folder_prefix=('2026-10-Тест ПО (Автоматизация)', 'ТЕСТ ЗАГРУЗКИ'),
        tree={'source': 'json', 'disk_id': TEST_DISK_ID,
              'exports': [{'path': tree_file.name, 'sha256': hashlib.sha256(raw).hexdigest()}]})
    return config, snapshot


def plan(config):
    report = build_plan(config, check_existing_documents=False)
    approved = {f['filename']: f for f in scope.manifest()['files']}
    operations = {}
    if len(report['operations']) != 2 or report['matching']['blocked_registry_types']:
        raise ValidationError('Нужны ровно два проверенных синтетических PDF.')
    for original in report['operations'].values():
        f = approved.get(original['filename'])
        if f is None:
            raise ValidationError('PDF отсутствует в разрешённом манифесте.')
        item = {**original, 'mode': 'batch-test-v2',
                'confirmation_policy': BATCH_CONFIRMATION_POLICY,
                'document_type': 'pdf', 'file_key': 'pdf', 'bundle_date': f['date'],
                'acceptance_manifest_sha256': scope.MANIFEST_SHA256}
        scope.validate_item(item)
        operations[fingerprint(item)] = item
    context = {'mode': 'two-folder-acceptance-v1', 'operations': operations,
               'manifest': scope.MANIFEST_SHA256}
    return report, context, operations


def check_duplicates(index, operations, checkpoints):
    for key, item in operations.items():
        known = checkpoints[key].get('document_id')
        for d in index.children.get(item['resolved_folder_id'], {}).values():
            if (d.name.casefold() == item['filename'].casefold()
                    or item['number'].casefold() in d.name.casefold()):
                if (d.id != known or d.is_folder or d.name != item['filename']
                        or checkpoints[key]['state'] not in {'ATTACHED', *BATCH_DOCUMENT_STATES}):
                    raise ValidationError('Обнаружен тестовый дубликат; новые POST запрещены.')


def run(*, output, confirmed=False, expected_plan=None):
    from sarex_loader.upload_workflow import _execute_batch

    if type(confirmed) is not bool or (not confirmed and expected_plan is not None):
        raise ValidationError('Неверный режим тестовой загрузки.')
    output = Path(output).absolute()
    if (output.parent != scope.artifact_path() or output.exists() or output.is_symlink()):
        raise ValidationError('Нужна новая подпапка результатов ограниченного теста.')
    with gateway_login() as token_provider:
        index, evidence = read_targets(token_provider)
        config, snapshot = prepare(index, output)
        report, context, operations = plan(config)
        checkpoints = {k: {'state': 'PLANNED'} for k in operations}
        if scope.journal_path().exists():
            previous_context, previous_operations, checkpoints = Journal.peek(scope.journal_path())
            if previous_context != fingerprint(context) or previous_operations != operations:
                raise ValidationError('Тестовый план изменён. Журнал нельзя заменить.')
        allowed = {'PLANNED', 'ATTACHED', *BATCH_DOCUMENT_STATES}
        if any(c['state'] not in allowed for c in checkpoints.values()):
            raise ValidationError('OUTCOME_UNKNOWN: тест остановлен; повтор POST запрещён.')
        check_duplicates(index, operations, checkpoints)
        digest = fingerprint(context)
        summary = {'plan_sha256': digest, 'manifest_sha256': scope.MANIFEST_SHA256,
                   'mode': 'TWO_FOLDER_ACCEPTANCE', 'dry_run': not confirmed,
                   'folders': evidence, 'operations': operations,
                   'server_completeness': 'UNKNOWN', 'max_documents': 2,
                   'completeness_exception': 'ONLY_TWO_PINNED_NEW_SYNTHETIC_DOCUMENTS',
                   'production_writes_enabled': False}
        if not confirmed:
            _write_bundle(output, {'acceptance.json': json.dumps(summary, ensure_ascii=False,
                                                                indent=2).encode()},
                          [config.input_root, scope.journal_path()])
            return summary
        if expected_plan != digest:
            raise ValidationError('SHA-256 тестового плана не подтверждён.')
        make_url_copy(snapshot, report['registry']['sha256'], [])
        with Journal(scope.journal_path(), [config.input_root]) as journal:
            journal.register(context, operations)
            # Re-check after the exclusive lock, immediately before the loader.
            fresh, summary['pre_post_get'] = read_targets(token_provider)
            check_duplicates(fresh, operations, journal.checkpoints())
            result = _execute_batch(config, {'max_documents': 2}, report, operations, journal,
                                    False, False, token_provider, acceptance=True)
            _verify_sources(config, report['registry'], report['matching']['files'],
                            report['pdf_directory_identity'])
            updates = [URLUpdate(operations[k]['sheet'], operations[k]['row'],
                                 operations[k]['row_id'], operations[k]['number'],
                                 f'https://lk.sarex.io/documentations/{identifier}')
                       for k, identifier in result['urls'].items()]
            workbook = make_url_copy(snapshot, report['registry']['sha256'], updates,
                                     approved_document_ids=tuple(result['urls'].values()))
            summary.update(result, urls_written=len(updates), checkpoints=journal.checkpoints(),
                           candidates={k: journal.response_candidates(k) for k in operations})
            _write_bundle(output, {'registry.test.xlsx': workbook,
                                  'acceptance.json': json.dumps(summary, ensure_ascii=False,
                                                               indent=2).encode()},
                          [config.input_root, scope.journal_path()])
        return summary


def command(argv):
    """Only a fixed acceptance subcommand; production -load remains disabled."""
    from sarex_loader.api_models import ApiError
    from sarex_loader.upload_workflow import run_acceptance_upload

    confirmed = len(argv) == 3 and argv[0] == '--confirm-test-upload'
    if not (len(argv) == 1 or confirmed):
        raise ValidationError('Нужен новый каталог результата; для записи — флаг и SHA-256 плана.')
    try:
        result = run_acceptance_upload(output=argv[-1], confirmed=confirmed,
                                       expected_plan=argv[1] if confirmed else None)
    except ApiError as exc:
        raise ValidationError('Проверка тестовых целей через API не завершена: '
                              f'{exc.code.value}. Запись запрещена.') from None
    print('Тестовый план SHA-256: ' + result['plan_sha256'])
    print('Проверка завершена.' if not confirmed else
          f"Загружено: {result['uploaded']}; подтверждено ранее: {result['already_confirmed']}; "
          f"URL в новой копии: {result['urls_written']}; ошибок: {len(result['errors'])}.")
    return 3 if result.get('stopped') else 0
