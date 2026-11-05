"""Manual single synthetic upload, fixed scope, fixed durable journal, preview by default."""

import getpass
import json
import sys
import warnings
from contextlib import nullcontext
from functools import partial
from pathlib import Path

from sarex_loader.api_client import ApiSettings, SarexClient
from sarex_loader.api_models import ApiError
from sarex_loader.auth import AuthSession
from sarex_loader.bundle_diagnostics import contract_preview
from sarex_loader.cli import SafeParser
from sarex_loader.gateway_diagnostic_policy import GatewayLoginPolicy
from sarex_loader.https_transport import ReadOnlyHTTPSTransport
from sarex_loader.journal import Journal
from sarex_loader.read_only_policy import AUTH_BASE, DOCUMENTATION_BASE
from sarex_loader.safety import ValidationError
from sarex_loader.single_test_config import load_single_test_config, single_journal_path
from sarex_loader.single_test_identity import EXCEL_OPERATION_ID, THIRD_OPERATION_ID
from sarex_loader.single_test_predecessor import independent_journal_path, predecessor_guard
from sarex_loader.single_test_prepare import prepare_independent, verify_prepared
from sarex_loader.single_test_scope import (
    TEST_DISK_ID,
    TEST_PARENT_ID,
    TEST_ROOT_ID,
    verify_created_document,
)
from sarex_loader.single_test_trace import run_stage
from sarex_loader.single_test_transport import PHASES, SingleTestHTTPSTransport, single_plan
from sarex_loader.synthetic_pdf import SyntheticPDF

CONFIRMATION = 'UPLOAD ONE SYNTHETIC PDF TO 7915046 IN 2093037'
THIRD_RISK_CONFIRMATION = 'ACK TWO PRIOR BUNDLES MAY EXIST NO RETRY'
EXCEL_RISK_CONFIRMATION = 'ACK THREE PRIOR OUTCOMES UNKNOWN NO RETRY'


def _write_phase(phase, config, checkpoint, client):
    if phase == 'CREATE_BUNDLE':
        return {'bundle_id': client.create_bundle(config.draft()).id}
    if phase == 'UPLOAD_SINGLE':
        client.upload_single(checkpoint['bundle_id'], config.key, SyntheticPDF(config.operation_id))
    elif phase == 'UPLOAD_FINISH':
        client.upload_finish(checkpoint['bundle_id'])
    else:
        return {'document_id': client.create_document(
            disk_id=TEST_DISK_ID, parent_id=TEST_PARENT_ID,
            name=config.draft().filename, bundle_id=checkpoint['bundle_id']).id}
    return {}


def execute_single(config, journal, client, *, diagnostics=False, upload_context=None,
                   before_request=None):
    """The transport independently enforces this same sequence and durable POST intent."""
    _, key, _ = single_plan(config, upload_context=upload_context)
    checkpoint = journal.checkpoint(key)
    def invoke(stage, action):
        if before_request is not None:
            before_request()
        return run_stage(stage, client, action) if diagnostics else action()
    invoke('GET_TARGET', partial(client.get_document, TEST_PARENT_ID))
    invoke('GET_TEST_ROOT', partial(client.get_document, TEST_ROOT_ID))
    if checkpoint['state'] != 'ATTACHED':
        invoke('GET_TYPES', client.get_document_types)
    while checkpoint['state'] in PHASES:
        phase = PHASES[checkpoint['state']]
        if before_request is not None:
            before_request()  # Changed input is rejected before durable POST intent.
        journal.begin_request(key, phase)
        try:
            result = invoke(phase, partial(_write_phase, phase, config, checkpoint, client))
            journal.confirm_request(key, **result)
        except BaseException:
            # If this durable update itself fails, IN_FLIGHT is recovered as UNKNOWN on restart.
            journal.unknown_request(key)
            raise
        checkpoint = journal.checkpoint(key)
    if checkpoint['state'] != 'ATTACHED':
        raise ValidationError('OUTCOME_UNKNOWN_OR_BLOCKED: повтор записи запрещён.')
    document = invoke('GET_CREATED_DOCUMENT',
                      partial(client.get_document, checkpoint['document_id']))
    verify_created_document(document, checkpoint['document_id'], expected_filename=config.filename)
    return {'status': 'SINGLE_DOCUMENT_VERIFIED', 'document_id': document.id,
            'parent_id': TEST_PARENT_ID, 'root_id': TEST_ROOT_ID,
            'url': f'https://lk.sarex.io/documentations/{document.id}',
            'journal_state': 'ATTACHED'}


def confirm_single(config):
    """Same explicit approval and residual-risk acknowledgement for both entry points."""
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValidationError('Для live-теста нужен интерактивный терминал.')
    confirmation = CONFIRMATION if config.operation_id is None else (
        f'UPLOAD INDEPENDENT TEST {config.operation_id} TO 7915046 ACK OLD BUNDLE UNKNOWN')
    print('Один синтетический PDF. Возможны частичные артефакты; POST не повторяются.\n'
          'Подтвердите: ' + confirmation, file=sys.stderr)
    if input() != confirmation:
        raise ValidationError('Подтверждение одиночной загрузки не получено.')
    if config.operation_id == THIRD_OPERATION_ID:
        print('Обе прежние операции UNKNOWN. Их Bundle могут существовать; '
              'этот тест их не повторяет и не закрывает.\n'
              'Отдельно подтвердите риск: ' + THIRD_RISK_CONFIRMATION, file=sys.stderr)
        if input() != THIRD_RISK_CONFIRMATION:
            raise ValidationError('Подтверждение риска двух старых Bundle не получено.')
    if config.operation_id == EXCEL_OPERATION_ID:
        print('Три прежних исхода не закрыты. Подтвердите риск: '
              + EXCEL_RISK_CONFIRMATION, file=sys.stderr)
        if input() != EXCEL_RISK_CONFIRMATION:
            raise ValidationError('Подтверждение риска прежних операций не получено.')


def run_authenticated_single(config, *, upload_context=None, before_request=None,
                             input_roots=None):
    """Reuse the fixed journal and real adapter; caller must obtain explicit approval."""
    auth = client = username = password = None
    try:
        if before_request is not None:
            before_request()
        if config.operation_id is not None:
            verify_prepared(config)
        guard = (predecessor_guard(config.operation_id)
                 if config.operation_id is not None else nullcontext())
        journal_path = (independent_journal_path(config.operation_id)
                        if config.operation_id is not None else single_journal_path())
        roots = input_roots or [Path(__file__).resolve().parent]
        with guard, Journal(journal_path, roots) as journal:
            transport = SingleTestHTTPSTransport(config, journal, confirmed=True,
                                                 upload_context=upload_context)
            login_transport = ReadOnlyHTTPSTransport(GatewayLoginPolicy(), confirmed=True)
            auth = AuthSession(ApiSettings(AUTH_BASE, ('https://lk.sarex.io',)),
                               transport=login_transport,
                               read_only_network_enabled=True, diagnostics_enabled=True)
            with warnings.catch_warnings():
                warnings.simplefilter('error', getpass.GetPassWarning)
                username = getpass.getpass('Login (скрытый ввод): ')
                password = getpass.getpass('Password (скрытый ввод): ')
            try:
                run_stage('AUTH_TOKEN', auth, partial(auth.login, username, password))
            finally:
                username = password = None
            client = SarexClient(ApiSettings(DOCUMENTATION_BASE, ('https://api.sarex.io',)),
                                 transport=transport,
                                 token_provider=lambda: auth.access_token(allow_refresh=False),
                                 single_test_network_enabled=True, diagnostics_enabled=True)
            return execute_single(config, journal, client, diagnostics=True,
                                  upload_context=upload_context, before_request=before_request)
    finally:
        if auth is not None:
            auth.logout()
        auth = client = username = password = None


def main(argv=None):
    parser = SafeParser(description='Один синтетический PDF, только фиксированная папка 99-Тест.')
    parser.add_argument('--config', required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--confirm-live-single', action='store_true')
    mode.add_argument('--prepare-independent', action='store_true')
    try:
        args = parser.parse_args(argv)
        config = load_single_test_config(args.config)
        if args.prepare_independent:
            print(json.dumps(prepare_independent(config)))
            return 0
        if not args.confirm_live_single:
            print(json.dumps({'mode': 'SINGLE_TEST_PREVIEW', 'network_started': False,
                              'write_enabled': False, 'max_documents': 1,
                              'disk_id': TEST_DISK_ID, 'root_id': TEST_ROOT_ID,
                              'parent_id': TEST_PARENT_ID,
                              'operation_id': config.operation_id,
                              'prior_artifacts_excluded': False,
                              'disk_evidence': 'USER_CONFIRMED_DOCUMENTATION_DISKS',
                              'create_bundle_request': contract_preview(config),
                              'response_contract': 'STRICT_LOCAL_PROJECTION_NOT_LIVE_VERIFIED'}))
            return 0
        confirm_single(config)
        print(json.dumps(run_authenticated_single(config)))
        return 0
    except (ApiError, ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print('Тест прерван. Проверьте журнал; не повторяйте неопределённый POST.', file=sys.stderr)
        return 130
    except Exception:
        print('Ошибка одиночного теста. Детали скрыты; нужна проверка журнала.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
