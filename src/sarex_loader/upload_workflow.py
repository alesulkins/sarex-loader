"""Script 1: local plan, offline simulation or the closed single-test, and a new XLSX."""

import hashlib
import json
import os
import sys
from functools import partial

from sarex_loader.api_client import ApiSettings, SarexClient
from sarex_loader.api_models import ApiError, ApiErrorCode
from sarex_loader.api_transport import BearerToken
from sarex_loader.excel_copy import URLUpdate, make_url_copy
from sarex_loader.file_safety import directory_fd, read_snapshot
from sarex_loader.journal import (
    BATCH_CONFIRMATION_POLICY,
    BATCH_DOCUMENT_STATES,
    Journal,
    fingerprint,
)
from sarex_loader.multipart import MultipartPDF
from sarex_loader.pdf_scan import identity
from sarex_loader.pipeline import _verify_sources, build_plan, run_pipeline
from sarex_loader.reports import _write_bundle
from sarex_loader.safety import ValidationError
from sarex_loader.upload_mock import MOCK_API, MOCK_ORIGIN, UploadMockTransport

PHASES = {
    'PLANNED': 'CREATE_BUNDLE', 'BUNDLE_CREATED': 'UPLOAD_SINGLE',
    'FILE_SENT': 'UPLOAD_FINISH', 'FINISHED': 'CREATE_DOCUMENT',
}


def _excel_identity(config):
    with directory_fd(config.excel.parent) as fd:
        return identity(os.stat(config.excel.name, dir_fd=fd, follow_symlinks=False))


def _perform(phase, client, target, body):
    if phase == 'CREATE_BUNDLE':
        bundle = client.create_bundle(target.draft)
        if bundle.id != target.bundle_id:
            raise ApiError(ApiErrorCode.INVALID_RESPONSE)
        return {'bundle_id': bundle.id}
    if phase == 'UPLOAD_SINGLE':
        client.upload_single(target.bundle_id, target.draft.key, body)
        return {}
    if phase == 'UPLOAD_FINISH':
        client.upload_finish(target.bundle_id)
        return {}
    document = client.create_document(
        disk_id=target.draft.disk_id, parent_id=target.parent_id,
        name=target.draft.filename, bundle_id=target.bundle_id)
    if document.id != target.document_id:
        raise ApiError(ApiErrorCode.INVALID_RESPONSE)
    return {'document_id': document.id}


def run_upload_workflow(config, *, simulate: bool = False,
                        allow_independent: bool = False, single_test_config=None,
                        confirm_live_single=False, expected_upload_plan_sha256=None,
                        register_single_plan=False, recover_document_id=None,
                        confirm_url_copy=False, read_tree=False, batch_config=None,
                        confirm_live_batch=False, expected_batch_plan=None,
                        recover_batch_urls=False, confirm_batch_urls=False,
                        document_only_urls=False, pdf_metadata_only=False,
                        stop_requested=None, write_original=False, backup_dir=None) -> dict:
    """No arbitrary client/transport/credentials injection.

    simulate=True explicitly selects the built-in in-memory fixture, never HTTPS.
    Default execution is local. Explicit single_test_config selects a separate,
    fixed-scope integration; it never authorizes bulk upload or new identities.
    """
    from sarex_loader.tree_source import validate_tree_mode

    if write_original and (not simulate or backup_dir is None):
        raise ValidationError('Запись переданного Excel пока разрешена только в mock-upload '
                              'с резервной копией; рабочий -load выключен.')
    if stop_requested is not None and (not simulate or not callable(stop_requested)):
        raise ValidationError('Штатная остановка этого режима доступна только в mock-upload.')
    validate_tree_mode(config.tree, read_tree)
    if (type(pdf_metadata_only) is not bool or pdf_metadata_only and (
            simulate or single_test_config is not None or confirm_live_batch
            or recover_batch_urls or confirm_batch_urls)):
        raise ValidationError('METADATA_PLAN_IS_READ_ONLY')
    if batch_config is not None:
        if (simulate or allow_independent or single_test_config is not None
                or confirm_live_single or register_single_plan or recover_document_id is not None
                or confirm_url_copy or expected_upload_plan_sha256 is not None):
            raise ValidationError('BATCH_MODE_CONFLICT')
        return run_batch_upload(config, batch_config, confirmed=confirm_live_batch,
                                expected_plan=expected_batch_plan, recover_urls=recover_batch_urls,
                                confirm_urls=confirm_batch_urls,
                                document_only_urls=document_only_urls, read_tree=read_tree,
                                pdf_metadata_only=pdf_metadata_only)
    if (confirm_live_batch or expected_batch_plan is not None or recover_batch_urls
            or confirm_batch_urls or document_only_urls):
        raise ValidationError('BATCH_CONFIG_REQUIRED')
    if (config.command != 'upload' or type(simulate) is not bool
            or type(allow_independent) is not bool or allow_independent and not simulate):
        raise ValidationError('Workflow разрешён только для upload.')
    if single_test_config is not None:
        if simulate or allow_independent:
            raise ValidationError('Нельзя смешивать mock и ограниченную live-интеграцию.')
        return _single_upload(config, single_test_config, confirmed=confirm_live_single,
                              expected_plan=expected_upload_plan_sha256,
                              register=register_single_plan, recover_id=recover_document_id,
                              confirm_copy=confirm_url_copy, read_tree=read_tree)
    if (confirm_live_single or expected_upload_plan_sha256 is not None or register_single_plan
            or recover_document_id is not None or confirm_url_copy):
        raise ValidationError('Нужен явный single-test-config; массовый live запрещён.')
    if not simulate:
        return run_pipeline(config, read_tree=read_tree, pdf_metadata_only=pdf_metadata_only)
    if config.journal_dir is None or config.output_dir is None:
        raise ValidationError('Для mock-upload нужны journal_dir и новый output_dir.')
    if config.output_dir.exists() or config.output_dir.is_symlink():
        raise ValidationError('Выходной каталог уже существует; перезапись запрещена.')
    with directory_fd(config.output_dir.parent):
        pass
    with Journal(config.journal_dir, [config.input_root]) as journal:
        report = build_plan(config, journal, read_tree=read_tree)
        directory_identity = report['pdf_directory_identity']
        if (report['outcome_unknown']
                or report['matching']['blocked_registry_types']):
            raise ValidationError('MOCK_PLAN_BLOCKED: реестр отклонён или есть OUTCOME_UNKNOWN.')
        transport = UploadMockTransport(report['operations'])
        # Hard boundary: no network adapter can be substituted through config or arguments.
        if type(transport) is not UploadMockTransport or transport.network_enabled is not False:
            raise ValidationError('Реальный транспорт загрузки запрещён.')
        client = SarexClient(
            ApiSettings(MOCK_API, (MOCK_ORIGIN,)), BearerToken('SYNTHETIC-UPLOAD-ONLY'),
            transport=transport, mock_writes_enabled=True,
        )
        before = _excel_identity(config)
        snapshot = read_snapshot(config.excel, config.max_file_bytes)
        if before != _excel_identity(config):
            raise ValidationError('INPUT_CHANGED: Excel изменился.')
        updates = {}
        for key, target in transport.targets.items():
            operation = report['operations'][key]
            updates[key] = URLUpdate(operation['sheet'], operation['row'], operation['row_id'],
                                     operation['number'], target.url)
            checkpoint = journal.checkpoint(key)
            if (checkpoint['bundle_id'] not in {None, target.bundle_id}
                    or checkpoint['document_id'] not in {None, target.document_id}):
                raise ValidationError('Журнал другого mock-сценария; сверка обязательна.')
        # Check copy compatibility/empty URLs before the first simulated API effect.
        make_url_copy(snapshot, report['registry']['sha256'], list(updates.values()))
        _verify_sources(config, report['registry'], report['matching']['files'], directory_identity)
        pending = any(c['state'] in PHASES for c in report['mock_checkpoints'].values())
        if pending:
            types = client.get_document_types()
            if sum(t.name == 'pdf' and any(f.key == 'pdf' and f.file and f.can_upload
                                          for f in t.fields) for t in types) != 1:
                raise ApiError(ApiErrorCode.INVALID_RESPONSE)
        written, url_errors = [], []
        stopped = False
        for key, target in transport.targets.items():
            # A signal handler sets a flag only. Finish the current file and its
            # durable confirmation before observing it; never interrupt a POST.
            if stop_requested is not None and stop_requested():
                stopped = True
                break
            checkpoint = journal.checkpoint(key)
            while checkpoint['state'] in PHASES:
                if _excel_identity(config) != before:
                    raise ValidationError('INPUT_CHANGED: Excel изменился; продолжение запрещено.')
                phase = PHASES[checkpoint['state']]
                # Validate one PDF per phase; never hold all PDF contents or scan all
                # operations here. A changed PDF stops BEFORE committing the next intent.
                with MultipartPDF(config.input_root, config.pdf_dir / target.draft.filename,
                                  expected_sha256=target.pdf_sha256) as body:
                    journal.run_mock_step(key, phase,
                                          partial(_perform, phase, client, target, body))
                checkpoint = journal.checkpoint(key)
            if checkpoint['state'] != 'ATTACHED':
                raise ValidationError('OUTCOME_UNKNOWN_OR_BLOCKED: повтор запрещён.')
            try:
                document = client.get_document(checkpoint['document_id'])
                if (document.name != target.draft.filename or document.is_folder
                        or document.disk_id != target.draft.disk_id):
                    raise ApiError(ApiErrorCode.INVALID_RESPONSE)
            except ApiError as exc:
                # ATTACHED stays durable. A later attempt retries only GET/export, not POST.
                url_errors.append({'operation_id': key, 'code': exc.code.value})
                continue
            journal.mark_mock_url_checked(key, document.id)
            written.append(updates[key])
        _verify_sources(config, report['registry'], report['matching']['files'], directory_identity)
        if before != _excel_identity(config):
            raise ValidationError('INPUT_CHANGED: Excel изменился перед публикацией.')
        workbook = make_url_copy(snapshot, report['registry']['sha256'], written)
        if write_original:
            from sarex_loader.excel_commit import commit_urls

            report['excel_commit'] = commit_urls(
                config.excel, snapshot, written, backup_dir=backup_dir)
        report['mock_checkpoints'] = journal.checkpoints()
        report['mock_upload'] = {
            'independent_records': True,
            'mode': 'BUILT_IN_SIMULATION', 'real_upload_performed': False,
            'status': ('MOCK_STOPPED' if stopped else
                       'MOCK_URL_PENDING' if url_errors else 'MOCK_COMPLETE'),
            'documents_attached': sum(c['state'] == 'ATTACHED'
                                      for c in report['mock_checkpoints'].values()),
            'urls_written': len(written),
            'url_errors': url_errors, 'http_calls_simulated': len(transport.calls),
            'pdf_bytes_streamed': transport.pdf_bytes,
            'max_pdf_chunk_bytes': transport.max_chunk_bytes,
            'output_file': 'registry.mock.xlsx',
            'output_sha256': hashlib.sha256(workbook).hexdigest(),
            'url_origin': MOCK_ORIGIN, 'targets_verified_in_sarex': False,
        }
        _write_bundle(config.output_dir, {
            'registry.mock.xlsx': workbook,
            'upload_workflow.json': json.dumps(report, ensure_ascii=True, indent=2).encode(),
        }, [config.input_root, config.journal_dir])
        return report


def _single_upload(config, single, *, confirmed, expected_plan, register=False,
                   recover_id=None, confirm_copy=False, read_tree=False):
    """Excel binding around the EXISTING closed single-test, not a new write policy.

    Preview does not open SQLite. The same fixed request journal owns all POST
    states and IDs, including on restart; the offline plan is not a second ledger.
    """
    from sarex_loader.single_test import confirm_single, run_authenticated_single
    from sarex_loader.single_test_config import SingleTestConfig, single_journal_path
    from sarex_loader.single_test_identity import EXCEL_OPERATION_ID, THIRD_OPERATION_ID
    from sarex_loader.single_test_predecessor import (
        created_document_evidence,
        independent_journal_path,
    )
    from sarex_loader.single_test_prepare import independent_pdf_path, register_excel_plan
    from sarex_loader.single_test_scope import TEST_DISK_ID, TEST_PARENT_ID, TEST_ROOT_ID
    from sarex_loader.synthetic_pdf import synthetic_pdf_bytes

    if type(confirmed) is not bool or type(single) is not SingleTestConfig:
        raise ValidationError('Некорректный режим одиночной интеграции.')
    if (type(register) is not bool or type(confirm_copy) is not bool
            or confirmed and (register or recover_id is not None or confirm_copy)
            or register and (recover_id is not None or confirm_copy)
            or confirm_copy and recover_id is None):
        raise ValidationError('Нельзя смешивать регистрацию, загрузку и восстановление.')
    if recover_id is not None:
        from sarex_loader.api_models import valid_id
        if not valid_id(recover_id) or single.operation_id not in {
                THIRD_OPERATION_ID, EXCEL_OPERATION_ID}:
            raise ValidationError('RECOVERY_DOCUMENT_NOT_ALLOWED')
    single.draft()  # Closed operation identity allowlist remains unchanged.
    fixed_journal = (single_journal_path() if single.operation_id is None
                     else independent_journal_path(single.operation_id))
    expected_root = TEST_ROOT_ID if config.tree is not None else TEST_PARENT_ID
    if (config.target_folder_id != str(expected_root) or config.journal_dir != fixed_journal
            or config.output_dir is None):
        raise ValidationError('Нужны точная тестовая цель, прежний журнал и новый output-dir.')
    output = config.output_dir
    if (output.exists() or output.is_symlink() or any(
            output.is_relative_to(p) or p.is_relative_to(output)
            for p in (config.input_root, fixed_journal))):
        raise ValidationError('Нужен отдельный новый выходной каталог.')
    with directory_fd(output.parent):
        pass
    # Read-only URL recovery expects the candidate to exist. This exception cannot
    # reach uploads: confirmed/register/recover combinations were rejected above.
    report = build_plan(config, read_tree=read_tree,
                        check_existing_documents=recover_id is None)
    if (report['status'] != 'LOCAL_PLAN_ONLY' or len(report['operations']) != 1
            or len(report['rows']) != 1):
        raise ValidationError('SINGLE_UPLOAD_PLAN_BLOCKED: нужна одна однозначная запись.')
    operation = next(iter(report['operations'].values()))
    if config.tree is not None:
        from sarex_loader.single_test_scope import TEST_PATH_IDS

        if (config.tree.disk_id != TEST_DISK_ID
                or operation['resolved_folder_id'] != TEST_PARENT_ID
                or tuple(operation['resolved_path_ids']) != TEST_PATH_IDS):
            raise ValidationError('SINGLE_RESOLVED_TARGET_NOT_AUTHORIZED')
    expected_pdf = synthetic_pdf_bytes(single.operation_id)
    if (operation['status'] != 'LOCAL_MATCH' or operation['filename'] != single.filename
            or operation['pdf_sha256'] != hashlib.sha256(expected_pdf).hexdigest()):
        raise ValidationError('SINGLE_UPLOAD_PDF_NOT_AUTHORIZED')
    if single.operation_id == EXCEL_OPERATION_ID and (
            config.pdf_dir / single.filename != independent_pdf_path(single)):
        raise ValidationError('EXCEL_TEST_PREPARED_PATH_REQUIRED')
    before = _excel_identity(config)
    snapshot = read_snapshot(config.excel, config.max_file_bytes)
    # Verify the same worksheet/row/empty URL and OOXML support before any HTTP.
    update = partial(URLUpdate, operation['sheet'], operation['row'],
                     operation['row_id'], operation['number'])
    make_url_copy(snapshot, report['registry']['sha256'],
                  [update('https://upload.example.invalid/documentations/1')])
    binding = {'mode': 'excel-single-test-v1', 'plan_id': report['plan_id'],
               'operation': operation, 'registry_sha256': report['registry']['sha256']}
    plan_hash = fingerprint({'binding': binding, 'draft': single.draft().payload(),
                             'operation_id': single.operation_id})
    if recover_id is not None:
        plan_hash = fingerprint({'plan': plan_hash, 'recover_document_id': recover_id})
    summary = {'mode': 'UPLOAD_SINGLE_TEST', 'dry_run': not confirmed,
               'network_enabled': confirmed, 'write_enabled': confirmed,
               'upload_plan_sha256': plan_hash, 'max_documents': 1,
               'disk_id': TEST_DISK_ID, 'root_id': TEST_ROOT_ID, 'parent_id': TEST_PARENT_ID,
               'target_resolution': 'EXPLICIT_TEST_PARENT_NOT_PATH_LOOKUP',
               'journal_accessed': False, 'journal_state': 'NOT_INSPECTED',
               'operation_id': single.operation_id,
               'ready_for_live': False, 'prior_unknown_operations_must_not_be_retried': True}
    if config.tree is not None:
        summary.update(tree=report['tree'], target_resolution='EXACT_TREE_PATH_THEN_FIXED_SCOPE',
                       network_enabled=confirmed or report['tree']['network_enabled'])

    def verify_inputs():
        if config.tree is not None:
            config.tree.verify_sources()
        _verify_sources(config, report['registry'], report['matching']['files'],
                        report['pdf_directory_identity'])
        if (_excel_identity(config) != before or
                read_snapshot(config.pdf_dir / single.filename, 8192) != expected_pdf):
            raise ValidationError('INPUT_CHANGED: одиночная загрузка остановлена.')

    verify_inputs()
    if not (confirmed or register or confirm_copy):
        if recover_id is not None:
            summary.update(mode='UPLOAD_URL_RECOVERY_PREVIEW', document_id=recover_id)
        return summary
    if expected_plan != plan_hash:
        raise ValidationError('UPLOAD_PLAN_CHANGED_OR_NOT_REVIEWED')
    if register:
        if single.operation_id != EXCEL_OPERATION_ID:
            raise ValidationError('NEW_EXCEL_OPERATION_REQUIRED')
        _manual_confirmation(f'REGISTER EXCEL TEST {single.operation_id} '
                             'ACK THREE PRIOR OUTCOMES UNKNOWN')
        verify_inputs()
        result = register_excel_plan(single, binding, [config.input_root, output])
        return {**summary, **result, 'journal_accessed': True, 'dry_run': False}
    if confirm_copy:
        from sarex_loader.single_test_diagnostic import fetch_recovery_document
        evidence_binding = None if single.operation_id == THIRD_OPERATION_ID else binding
        with created_document_evidence(single, recover_id,
                                       upload_context=evidence_binding) as evidence:
            result = fetch_recovery_document(single, evidence)
            if (not result['bundle_link_confirmed'] and result['bundle_reason'] not in {
                    'BUNDLES_NOT_EXPANDED', 'BUNDLES_ABSENT'}):
                raise ValidationError('RECOVERY_BUNDLE_CONTRADICTION')
            verify_inputs()
            print('Подтвердите содержимое PDF в интерфейсе Sarex для этого ID. '
                  'Локальный SHA256: ' + operation['pdf_sha256'], file=sys.stderr)
            _manual_confirmation(f'I VERIFIED PDF CONTENT {recover_id} FOR {single.operation_id}')
            verify_inputs()
            url = f'https://lk.sarex.io/documentations/{recover_id}'
            workbook = make_url_copy(snapshot, report['registry']['sha256'], [update(url)],
                                     approved_document_ids=(recover_id,))
            verify_inputs()
            summary.update(mode='MANUAL_URL_RECOVERY',
                           status='URL_COPY_CREATED_OPERATION_UNRESOLVED',
                           dry_run=False, network_enabled=True, write_enabled=False,
                           journal_accessed=True, journal_modified=False,
                           journal_state=result['journal_state'], document_id=recover_id, url=url,
                           bundle_link_confirmed=result['bundle_link_confirmed'],
                           bundle_reason=result['bundle_reason'], pdf_content_attested_by_user=True,
                           server_content_hash_verified=False, urls_written=1,
                           output_file='registry.recovered.xlsx',
                           output_sha256=hashlib.sha256(workbook).hexdigest())
            _write_bundle(output, {'registry.recovered.xlsx': workbook,
                                   'upload_workflow.json': json.dumps(summary).encode()},
                          [config.input_root, fixed_journal])
        return summary
    confirm_single(single)
    result = run_authenticated_single(single, upload_context=binding,
                                      before_request=verify_inputs,
                                      input_roots=[config.input_root, output])
    verify_inputs()
    # The real adapter has validated the document, path AND explicit Bundle projection.
    # If GET fails, its ATTACHED checkpoint survives; another export sends no POST.
    workbook = make_url_copy(snapshot, report['registry']['sha256'], [update(result['url'])],
                             approved_document_ids=(result['document_id'],))
    verify_inputs()  # Serialization must not hide a concurrent source replacement.
    summary.update(status='DOCUMENT_VERIFIED_COPY_CREATED', journal_accessed=True,
                   journal_state=result['journal_state'], document_id=result['document_id'],
                   url=result['url'], urls_written=1, output_file='registry.upload.xlsx',
                   output_sha256=hashlib.sha256(workbook).hexdigest())
    _write_bundle(output, {
        'registry.upload.xlsx': workbook,
        'upload_workflow.json': json.dumps(summary, ensure_ascii=True, indent=2).encode(),
    }, [config.input_root, fixed_journal])
    return summary


def _manual_confirmation(phrase):
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValidationError('Нужен интерактивный терминал.')
    print('Подтвердите: ' + phrase, file=sys.stderr)
    if input() != phrase:
        raise ValidationError('Явное подтверждение не получено.')


def load_batch_config(path):
    """Small explicit batch envelope; upload's existing RunConfig owns all sources/rules."""
    import tomllib
    from pathlib import Path

    from sarex_loader.api_upload_models import BundleDraft
    from sarex_loader.single_test_scope import TEST_DISK_ID

    try:
        values = tomllib.loads(read_snapshot(Path(path).absolute(), 8192).decode())
        if (set(values) != {'mode', 'document_type', 'key', 'date', 'max_documents'}
                or values['mode'] != 'batch-test'
                or type(values['max_documents']) is not int
                or not 1 <= values['max_documents'] <= 1000):
            raise ValueError
        BundleDraft(TEST_DISK_ID, values['document_type'], values['key'],
                    'validation.pdf', values['date'])
        return values
    except Exception:
        raise ValidationError('BATCH_CONFIG_INVALID') from None


def _batch_plan(config, options, *, read_tree=False, pdf_metadata_only=False):
    from sarex_loader.single_test_identity import (
        EXCEL_OPERATION_ID,
        INDEPENDENT_OPERATION_ID,
        THIRD_OPERATION_ID,
        independent_filename,
    )
    from sarex_loader.single_test_scope import TEST_DISK_ID, TEST_FILENAME, TEST_PATH_IDS
    from sarex_loader.single_test_transport import batch_journal_path
    from sarex_loader.synthetic_pdf import synthetic_pdf_bytes

    gateway = config.tree is not None and config.tree.source == 'gateway'
    if (config.command != 'upload' or config.tree is None
            or config.tree.source not in {'json', 'gateway'}
            or config.tree.disk_id != TEST_DISK_ID
            or not gateway and config.journal_dir != batch_journal_path()):
        raise ValidationError('BATCH_REQUIRES_JSON_TREE_AND_FIXED_JOURNAL')
    if gateway != read_tree:
        raise ValidationError('BATCH_GATEWAY_REQUIRES_READ_TREE')
    report = build_plan(config, read_tree=read_tree, pdf_metadata_only=pdf_metadata_only)
    previous_ids = (None, INDEPENDENT_OPERATION_ID, THIRD_OPERATION_ID, EXCEL_OPERATION_ID)
    previous_hashes = {hashlib.sha256(synthetic_pdf_bytes(i)).hexdigest() for i in previous_ids}
    previous_names = {TEST_FILENAME, *(independent_filename(i) for i in previous_ids if i)}
    operations = {}
    for original in report['operations'].values():
        item = {**original, 'mode': 'batch-test-v2',
                'confirmation_policy': BATCH_CONFIRMATION_POLICY,
                'document_type': options['document_type'],
                'file_key': options['key'], 'bundle_date': options['date']}
        if item['status'] == 'LOCAL_MATCH':
            if (item['resolved_folder_id'] != TEST_PATH_IDS[-1]
                    or tuple(item['resolved_path_ids']) != TEST_PATH_IDS):
                item['status'] = 'TARGET_NOT_AUTHORIZED'
            elif item['pdf_sha256'] in previous_hashes or item['filename'] in previous_names:
                item['status'] = 'OLD_OPERATION_REPLAY_FORBIDDEN'
        if gateway:
            accepted = report['tree']['operational_acceptance']['accepted_for_operational_checks']
            item['upload_blockers'] = ([] if accepted else ['TREE_COMPLETENESS_UNVERIFIED'])
            if pdf_metadata_only:
                item['upload_blockers'].append('PDF_CONTENT_NOT_VERIFIED')
            if item['status'] != 'LOCAL_MATCH':
                item['upload_blockers'].append(item['status'])
            elif not accepted:
                item['status'] = 'TREE_COMPLETENESS_UNVERIFIED'
            item['upload_blockers'].append('PRODUCTION_ACCEPTANCE_REQUIRED')
        key = fingerprint(item)
        operations[key] = item
    context = {'mode': 'batch-test-v2', 'plan_id': report['plan_id'],
               'operations': operations}
    if gateway:
        context.update(mode='gateway-batch-preview-v1', tree_sha256=report['tree']['sha256'])
    return report, context, operations


def run_batch_upload(config, options, *, confirmed=False, expected_plan=None,
                     recover_urls=False, confirm_urls=False, document_only_urls=False,
                     read_tree=False, pdf_metadata_only=False):
    """Sequential branch of upload; reuses its plan/writer and the existing live adapter.

    No generic injected client, journal path, folder allowlist or POST callback.
    Explicit URL-only evidence is separate from journal operation completion.
    """
    from collections import Counter

    from sarex_loader.single_test_transport import batch_journal_path

    if (any(type(v) is not bool
            for v in (confirmed, recover_urls, confirm_urls, document_only_urls))
            or confirmed and recover_urls or confirm_urls and not recover_urls
            or document_only_urls and not recover_urls
            or type(options.get('max_documents')) is not int
            or not 1 <= options['max_documents'] <= 1000):
        raise ValidationError('BATCH_MODE_INVALID')
    report, context, operations = _batch_plan(
        config, options, read_tree=read_tree, pdf_metadata_only=pdf_metadata_only)
    gateway = config.tree.source == 'gateway'
    checkpoints = {k: {'state': 'PLANNED' if v['status'] == 'LOCAL_MATCH' else 'BLOCKED'}
                   for k, v in operations.items()}
    path = batch_journal_path()
    if (path.exists() or path.is_symlink()) and not gateway:
        stored_context, stored_operations, checkpoints = Journal.peek(path)
        if stored_context != fingerprint(context) or stored_operations != operations:
            raise ValidationError('BATCH_PLAN_CHANGED: журнал нельзя заменить для повтора.')
    unresolved = any(c['state'] not in {'PLANNED', 'BLOCKED', 'ATTACHED', *BATCH_DOCUMENT_STATES}
                     for c in checkpoints.values())
    pending = [k for k in operations if checkpoints[k]['state'] == 'PLANNED']
    states = {k: {f: v.get(f) for f in ('state', 'phase', 'bundle_id', 'document_id')}
              for k, v in checkpoints.items()}
    digest = fingerprint({'context': context, 'limit': options['max_documents'], 'states': states,
                          'document_only_urls': document_only_urls, 'recover_urls': recover_urls})
    blocked = [v for v in operations.values() if v['status'] not in {
        'LOCAL_MATCH', 'EXISTING_URL', 'REMOTE_DOCUMENT_EXISTS', 'NOT_FOUND'}]
    summary = {'mode': 'BATCH_UPLOAD', 'dry_run': not (confirmed or confirm_urls),
               'network_enabled': False, 'write_enabled': False,
               'plan_sha256': digest, 'max_documents': options['max_documents'],
               'eligible': len(pending), 'selected': min(len(pending), options['max_documents']),
               'folders': sorted({v['resolved_folder_id'] for v in operations.values()
                                  if v.get('resolved_folder_id') is not None}),
               'skips': dict(Counter(v['status'] for v in operations.values()
                                    if v['status'] != 'LOCAL_MATCH')),
               'reconciliation_required': unresolved,
               'verification_pending': sum(c['state'] == 'DOCUMENT_CREATED'
                                           for c in checkpoints.values()),
               'confirmation_policy': BATCH_CONFIRMATION_POLICY,
               'blocked': bool(unresolved or report['matching']['blocked_registry_types']
                               or not pending and blocked),
               'blocked_files': len(blocked),
               'document_only_url_policy': document_only_urls,
               'server_completeness': 'UNKNOWN', 'operations': operations}
    if gateway:
        # Never register a new Gateway plan into a historical fixed-scope journal.
        # Existing unresolved history remains untouched and cannot be replayed here.
        summary.update(mode='GATEWAY_BATCH_PREVIEW', tree=report['tree'],
                       network_enabled=report['tree']['network_enabled'],
                       blocked=True, upload_authorized=False, journal_updated=False,
                       pdf_metadata_only=pdf_metadata_only,
                       registry=report['registry'], rows=report['rows'],
                       matching=report['matching'],
                       write_blockers=([] if report['tree']['operational_acceptance'][
                           'accepted_for_operational_checks'] else ['TREE_COMPLETENESS_UNVERIFIED'])
                       + ['PRODUCTION_ACCEPTANCE_REQUIRED'])
        if confirmed or recover_urls or confirm_urls:
            raise ValidationError('BATCH_GATEWAY_COMPLETENESS_AND_ACCEPTANCE_REQUIRED')
        if config.output_dir is not None:
            from sarex_loader.tree_source import snapshot_payloads

            payloads = {'batch.json': json.dumps(summary, ensure_ascii=True, indent=2).encode()}
            if 'tree_snapshot' in report:
                payloads.update(snapshot_payloads(report['tree_snapshot'],
                                                  config.tree.max_response_bytes))
            _write_bundle(config.output_dir, payloads,
                          [p for p in (config.input_root, config.journal_dir, path)
                           if p is not None])
    if not (confirmed or confirm_urls):
        return summary
    if expected_plan != digest:
        raise ValidationError('BATCH_PLAN_CHANGED_OR_NOT_REVIEWED')
    if not recover_urls and summary['blocked']:
        raise ValidationError('BATCH_RECONCILIATION_OR_INPUT_REVIEW_REQUIRED')
    if recover_urls and not path.exists():
        raise ValidationError('BATCH_RECOVERY_REQUIRES_EXISTING_JOURNAL')
    output = config.output_dir
    if output is None or output.exists() or output.is_symlink() or any(
            output.is_relative_to(p) or p.is_relative_to(output)
            for p in (config.input_root, path)):
        raise ValidationError('BATCH_NEW_OUTPUT_REQUIRED')
    with directory_fd(output.parent):
        pass
    snapshot = read_snapshot(config.excel, config.max_file_bytes)
    make_url_copy(snapshot, report['registry']['sha256'], [])
    phrase = ('READ BATCH URLS' if recover_urls else
              f'UPLOAD AT MOST {summary["selected"]} PDF TO 7915046 ACK THREE OLD UNKNOWN')
    _manual_confirmation(phrase + (' ACCEPT DOCUMENT IDENTITY URLS' if document_only_urls else ''))
    with Journal(path, [config.input_root]) as journal:
        journal.register(context, operations)
        actual = {k: {f: v.get(f) for f in ('state', 'phase', 'bundle_id', 'document_id')}
                  for k, v in journal.checkpoints().items()}
        if actual != states:
            raise ValidationError('BATCH_STATE_CHANGED: нужен новый preview.')
        result = _authenticated_batch(config, options, report, operations, journal,
                                      recover_urls, document_only_urls)
        _verify_sources(config, report['registry'], report['matching']['files'],
                        report['pdf_directory_identity'])
        updates = [URLUpdate(operations[k]['sheet'], operations[k]['row'], operations[k]['row_id'],
                             operations[k]['number'], f'https://lk.sarex.io/documentations/{i}')
                   for k, i in result.pop('urls').items()]
        identifiers = tuple(int(u.url.rsplit('/', 1)[1]) for u in updates)
        workbook = make_url_copy(snapshot, report['registry']['sha256'], updates,
                                 approved_document_ids=identifiers)
        summary.update(result, dry_run=False, network_enabled=True, write_enabled=confirmed,
                       urls_written=len(updates), checkpoints=journal.checkpoints(),
                       candidates={k: journal.response_candidates(k) for k in operations},
                       output_file='registry.batch.xlsx')
        summary['reconciliation_required'] = any(
            c['state'] not in {'PLANNED', 'BLOCKED', 'ATTACHED', *BATCH_DOCUMENT_STATES}
            for c in summary['checkpoints'].values())
        summary['verification_pending'] = sum(c['state'] == 'DOCUMENT_CREATED'
                                              for c in summary['checkpoints'].values())
        summary['document_results'] = {
            k: {'document_id': c['document_id'],
                'create_post_confirmed': c['state'] in {'ATTACHED', *BATCH_DOCUMENT_STATES},
                'get_verified': c['url_status'] == 'DOCUMENT_CHECKED',
                'bundle_link': 'CONFIRMED' if c['state'] == 'ATTACHED' else 'UNCONFIRMED',
                'post_outcome_unknown': c['state'] == 'OUTCOME_UNKNOWN'}
            for k, c in summary['checkpoints'].items()}
        _write_bundle(output, {'registry.batch.xlsx': workbook,
                              'batch.json': json.dumps(summary, ensure_ascii=True,
                                                       indent=2).encode()},
                      [config.input_root, path])
        return summary


def _authenticated_batch(config, options, report, operations, journal, recover, document_only):
    import getpass
    import warnings

    from sarex_loader.auth import AuthSession
    from sarex_loader.gateway_diagnostic_policy import GatewayLoginPolicy
    from sarex_loader.https_transport import ReadOnlyHTTPSTransport
    from sarex_loader.read_only_policy import AUTH_BASE

    auth = None
    result = {'urls': {}, 'uploaded': 0, 'already_confirmed': 0, 'errors': [], 'stopped': False}
    try:
        auth = AuthSession(ApiSettings(AUTH_BASE, ('https://lk.sarex.io',)),
                           transport=ReadOnlyHTTPSTransport(GatewayLoginPolicy(), confirmed=True),
                           read_only_network_enabled=True)
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            username = getpass.getpass('Логин Sarex (скрытый ввод): ')
            password = getpass.getpass('Пароль Sarex (скрытый ввод): ')
        try:
            auth.login(username, password)
        finally:
            username = password = None
        return _execute_batch(config, options, report, operations, journal, recover,
                              document_only, lambda: auth.access_token(allow_refresh=False))
    except (ApiError, ValidationError) as exc:
        result['errors'].append({'stage': 'AUTH', 'code': str(exc)})
        result['stopped'] = True
        return result
    finally:
        if auth is not None:
            auth.logout()


def _execute_batch(config, options, report, operations, journal, recover, document_only,
                   token_provider, *, acceptance=False):
    """Shared sequential loader; transport owns every mutation authorization."""
    from sarex_loader.read_only_policy import DOCUMENTATION_BASE
    from sarex_loader.single_test_scope import TEST_DISK_ID, TEST_ROOT_ID
    from sarex_loader.single_test_transport import SingleTestHTTPSTransport

    result = {'urls': {}, 'uploaded': 0, 'already_confirmed': 0, 'errors': [], 'stopped': False}
    # Recheck existing documents before starting ANY independent new PDF.
    ordered = sorted(operations, key=lambda k: journal.checkpoint(k)['state'] == 'PLANNED')
    for key in ordered:
        item = operations[key]
        checkpoint = journal.checkpoint(key)
        if item['status'] != 'LOCAL_MATCH':
            continue
        state = checkpoint['state']
        known = [c['document_id'] for c in journal.response_candidates(key)
                 if c['phase'] == 'CREATE_DOCUMENT']
        if recover and not (state in {'ATTACHED', *BATCH_DOCUMENT_STATES}
                            or state == 'OUTCOME_UNKNOWN' and known):
            continue
        if (not recover and state == 'PLANNED'
                and result['uploaded'] >= options['max_documents']):
            continue
        def verify():
            _verify_sources(config, report['registry'], report['matching']['files'],
                            report['pdf_directory_identity'])
        try:
            verify()
            transport = SingleTestHTTPSTransport.for_batch(
                journal, key, confirmed=True, url_only=recover, document_only=document_only,
                    acceptance=acceptance)
            client = SarexClient(ApiSettings(DOCUMENTATION_BASE, ('https://api.sarex.io',)),
                                 transport=transport,
                                 token_provider=token_provider,
                                 single_test_network_enabled=True)
            client.get_document(item['resolved_folder_id'])
            client.get_document(TEST_ROOT_ID)
            if state == 'PLANNED':
                client.get_document_types()
            while not recover and checkpoint['state'] in PHASES:
                phase = PHASES[checkpoint['state']]
                verify()
                # Validate bytes before intent; stream the SAME file for upload_single.
                with MultipartPDF(config.input_root, config.pdf_dir / item['filename'],
                                  expected_sha256=item['pdf_sha256']) as body:
                    journal.begin_request(key, phase)
                    try:
                        if phase == 'CREATE_BUNDLE':
                            outcome = {'bundle_id': client.create_bundle(transport._config).id}
                        elif phase == 'UPLOAD_SINGLE':
                            client.upload_single(checkpoint['bundle_id'],
                                                 item['file_key'], body)
                            outcome = {}
                        elif phase == 'UPLOAD_FINISH':
                            client.upload_finish(checkpoint['bundle_id'])
                            outcome = {}
                        else:
                            outcome = {'document_id': client.create_document(
                                disk_id=TEST_DISK_ID, parent_id=item['resolved_folder_id'],
                                name=item['filename'], bundle_id=checkpoint['bundle_id']).id}
                            if not transport.response_diagnostic['bundle_link_confirmed']:
                                outcome['document_created_only'] = True
                        journal.confirm_request(key, **outcome)
                    except BaseException:
                        journal.unknown_request(key)
                        raise
                checkpoint = journal.checkpoint(key)
            identifier = checkpoint['document_id'] or (known[0] if recover and known else None)
            client.get_document(identifier)
            if checkpoint['state'] == 'OUTCOME_UNKNOWN':
                journal.mark_document_url_checked(key, identifier)
            else:
                journal.confirm_batch_document_get(
                    key, identifier, bundle_link_confirmed=
                    transport.response_diagnostic['bundle_link_confirmed'])
            result['urls'][key] = identifier
            if acceptance:
                result.setdefault('get_verified_documents', {})[key] = (
                    transport.response_diagnostic['verified_document'])
            result['already_confirmed' if state != 'PLANNED' else 'uploaded'] += 1
        except (ApiError, ValidationError) as exc:
            result['errors'].append({'operation': key, 'code': str(exc)})
            result['stopped'] = True
            break  # Even a GET failure stops this run; no subsequent resource mutation.
    return result


def run_acceptance_upload(*, output, confirmed=False, expected_plan=None):
    """Separate pinned exercise using this module's common plan/POST/SQLite chain."""
    from sarex_loader.acceptance_upload import run

    return run(output=output, confirmed=confirmed, expected_plan=expected_plan)
