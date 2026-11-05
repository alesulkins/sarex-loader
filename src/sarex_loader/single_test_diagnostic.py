"""One auth POST and three fixed GETs; never opens or modifies the upload journal."""

import getpass
import json
import sys
import warnings
from functools import partial

from sarex_loader.api_client import ApiSettings, SarexClient
from sarex_loader.api_models import ApiError, parse_document, valid_id
from sarex_loader.auth import AuthSession
from sarex_loader.bundle_diagnostics import document_bundle_observation
from sarex_loader.cli import SafeParser
from sarex_loader.gateway_diagnostic_policy import GatewayLoginPolicy
from sarex_loader.https_transport import ReadOnlyHTTPSTransport
from sarex_loader.read_only_policy import AUTH_BASE, DOCUMENTATION_BASE, ReadOnlyPolicy
from sarex_loader.safety import ValidationError
from sarex_loader.single_test_config import load_single_test_config
from sarex_loader.single_test_identity import EXCEL_OPERATION_ID, THIRD_OPERATION_ID
from sarex_loader.single_test_predecessor import created_document_evidence
from sarex_loader.single_test_scope import (
    TEST_PARENT_ID,
    TEST_ROOT_ID,
    verify_created_document,
    verify_pdf_type,
    verify_root_document,
    verify_target_document,
)
from sarex_loader.single_test_trace import run_stage
from sarex_loader.test_target_policy import SingleTestReadPolicy

CONFIRMATION = 'READ ONLY SINGLE TEST 2093037 7915046'
CREATED_DOCUMENT_ID = 7978396
CREATED_CONFIRMATION = 'READ ONLY CREATED DOCUMENT 7978396'


def inspect_created_document(client, config, evidence):
    """One exact GET; compare names in RAM and never turn a candidate into a checkpoint."""
    identifier = evidence['document_id']
    if (not valid_id(identifier)
            or config.operation_id not in {THIRD_OPERATION_ID, EXCEL_OPERATION_ID}
            or config.operation_id == THIRD_OPERATION_ID and identifier != CREATED_DOCUMENT_ID):
        raise ValidationError('CREATED_DOCUMENT_SCOPE_MISMATCH')
    value = client._exchange('GET', f'/v1/documents/{identifier}')
    document = parse_document(value)
    verify_created_document(document, identifier, expected_filename=config.filename)
    if 'parent_id' in value and (type(value['parent_id']) is not int
                                 or value['parent_id'] != TEST_PARENT_ID):
        raise ValidationError('TEST_DOCUMENT_PARENT_MISMATCH')
    binding = document_bundle_observation(value, evidence['bundle_id'], identifier)
    return {'status': ('DOCUMENT_AND_BUNDLE_VERIFIED_PENDING_RECONCILIATION'
                       if binding['bundle_link_confirmed'] else 'BUNDLE_LINK_UNCONFIRMED'),
            'stage': 'GET_CREATED_DOCUMENT',
            'http_status': client.response_diagnostic.get('http_status'),
            'document_id': identifier, 'document_checks_passed': True,
            'name_matches': True, 'path_and_parent_match': True, 'is_folder': False,
            **binding, 'journal_state': evidence.get('journal_state', 'OUTCOME_UNKNOWN'),
            'journal_modified': False,
            'write_enabled': False}


def fetch_recovery_document(config, evidence):
    """One auth POST and one exact GET; caller holds read-only journal evidence locks."""
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValidationError('Нужен интерактивный терминал.')
    phrase = f'READ ONLY URL RECOVERY {evidence["document_id"]}'
    print('Только авторизация и один GET. Подтвердите: ' + phrase, file=sys.stderr)
    if input() != phrase:
        raise ValidationError('Подтверждение read-only восстановления не получено.')
    auth = token = username = password = None
    try:
        auth = AuthSession(ApiSettings(AUTH_BASE, ('https://lk.sarex.io',)),
                           transport=ReadOnlyHTTPSTransport(GatewayLoginPolicy(), confirmed=True),
                           read_only_network_enabled=True)
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            username = getpass.getpass('Login (скрытый ввод): ')
            password = getpass.getpass('Password (скрытый ввод): ')
        auth.login(username, password)
        token = auth.access_token(allow_refresh=False)
        username = password = None
        auth.logout()
        client = SarexClient(
            ApiSettings(DOCUMENTATION_BASE, ('https://api.sarex.io',)), token,
            transport=ReadOnlyHTTPSTransport(
                ReadOnlyPolicy((evidence['document_id'],), max_requests=1), confirmed=True),
            read_only_network_enabled=True, diagnostics_enabled=True)
        return inspect_created_document(client, config, evidence)
    finally:
        if auth is not None:
            auth.logout()
        auth = token = username = password = None


def inspect_preflight(client, config):
    run_stage('GET_TARGET', client, partial(client.get_document, TEST_PARENT_ID),
              verify_target_document)
    run_stage('GET_TEST_ROOT', client, partial(client.get_document, TEST_ROOT_ID),
              verify_root_document)
    run_stage('GET_TYPES', client, client.get_document_types,
              partial(verify_pdf_type, config=config))


def main(argv=None):
    parser = SafeParser(description='Диагностика single-test: авторизация и три GET, без загрузки.')
    parser.add_argument('--config', required=True)
    parser.add_argument('--confirm-read-only', action='store_true')
    parser.add_argument('--created-document', action='store_true',
                        help='Только GET 7978396 и сравнение с кандидатами третьего журнала.')
    auth = token = client = username = password = None
    try:
        args = parser.parse_args(argv)
        config = load_single_test_config(args.config)
        if args.created_document and config.operation_id != THIRD_OPERATION_ID:
            raise ValidationError('CREATED_DOCUMENT_SCOPE_MISMATCH')
        if not args.confirm_read_only:
            print(json.dumps({'mode': 'SINGLE_TEST_DIAGNOSTIC_PREVIEW', 'network_started': False,
                              'write_enabled': False, 'max_auth_posts': 1,
                              'max_gets': 1 if args.created_document else 3,
                              'journal_accessed': False}))
            return 0
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            raise ValidationError('Нужен интерактивный терминал со скрытым вводом.')
        confirmation = CREATED_CONFIRMATION if args.created_document else CONFIRMATION
        print('Только авторизация и разрешённые GET. Журнал загрузки не изменяется.\n'
              'Подтвердите: ' + confirmation, file=sys.stderr)
        if input() != confirmation:
            raise ValidationError('Подтверждение read-only диагностики не получено.')
        if args.created_document:
            with created_document_evidence(config, CREATED_DOCUMENT_ID):
                pass  # Reject invalid evidence before even authenticating.
        auth = AuthSession(
            ApiSettings(AUTH_BASE, ('https://lk.sarex.io',)),
            transport=ReadOnlyHTTPSTransport(GatewayLoginPolicy(), confirmed=True),
            read_only_network_enabled=True, diagnostics_enabled=True)
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            username = getpass.getpass('Login (скрытый ввод): ')
            password = getpass.getpass('Password (скрытый ввод): ')
        try:
            run_stage('AUTH_TOKEN', auth, partial(auth.login, username, password))
            token = auth.access_token(allow_refresh=False)
        finally:
            username = password = None
            auth.logout()
        client = SarexClient(
            ApiSettings(DOCUMENTATION_BASE, ('https://api.sarex.io',)), token,
            transport=ReadOnlyHTTPSTransport(
                ReadOnlyPolicy((CREATED_DOCUMENT_ID,), max_requests=1)
                if args.created_document else SingleTestReadPolicy(), confirmed=True),
            read_only_network_enabled=True, diagnostics_enabled=True)
        if args.created_document:
            with created_document_evidence(config, CREATED_DOCUMENT_ID) as evidence:
                result = inspect_created_document(client, config, evidence)
            print(json.dumps(result))
            return 0 if result['bundle_link_confirmed'] else 3
        inspect_preflight(client, config)
        print(json.dumps({'status': 'PREFLIGHT_VERIFIED', 'write_enabled': False,
                          'journal_accessed': False}))
        return 0
    except (ApiError, ValidationError):
        if client is not None and args.created_document:
            print(json.dumps({'stage': 'GET_CREATED_DOCUMENT', **client.response_diagnostic,
                              'journal_modified': False, 'write_enabled': False}), file=sys.stderr)
        print('SINGLE_TEST_DIAGNOSTIC_FAILED: смотрите безопасный stage выше.', file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print('Read-only диагностика прервана; повторов нет.', file=sys.stderr)
        return 130
    except Exception:
        print('SINGLE_TEST_DIAGNOSTIC_FAILED: детали скрыты.', file=sys.stderr)
        return 1
    finally:
        if auth is not None:
            auth.logout()
        auth = token = client = username = password = None


if __name__ == '__main__':
    raise SystemExit(main())
