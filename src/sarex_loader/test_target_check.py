"""Manual test-folder preflight: one token POST, three exact GETs, zero resource writes."""

import getpass
import json
import sys
import warnings

from sarex_loader.api_client import ApiSettings, SarexClient
from sarex_loader.api_models import ApiError
from sarex_loader.auth import AuthSession
from sarex_loader.cli import SafeParser
from sarex_loader.gateway_diagnostic_policy import GatewayLoginPolicy
from sarex_loader.https_transport import ReadOnlyHTTPSTransport
from sarex_loader.read_only_policy import AUTH_BASE, DOCUMENTATION_BASE
from sarex_loader.safety import ValidationError
from sarex_loader.target_diagnostics import diagnose_target_result
from sarex_loader.target_response_trace import TargetResponseTrace, emit_stage
from sarex_loader.test_disk_config import (
    check_new_config_path,
    load_test_disk_config,
    save_verified_test_disk,
)
from sarex_loader.test_target import inspect_target, validate_disk_id
from sarex_loader.test_target_policy import TEST_PARENT_ID, TEST_ROOT_ID, TestTargetReadPolicy

CONFIRMATION = 'READ ONLY TEST 2093037 7915046'


def main(argv=None):
    parser = SafeParser(description='Только проверка метаданных целевой папки в 99-Тест.')
    parser.add_argument('--confirm-read-only', action='store_true')
    parser.add_argument('--diagnose-metadata', action='store_true',
                        help='Классификация disk_id/path без сырых значений; только три GET.')
    parser.add_argument('--diagnose-responses', action='store_true',
                        help='Этап, HTTP-статус, типы полей и причина отказа; без значений.')
    parser.add_argument('--expected-disk-id',
                        help='UUID для точной сверки; сам по себе не подтверждает диск.')
    parser.add_argument('--test-disk-config',
                        help='Явная конфигурация с фиксированным TEST_DISK_ID.')
    parser.add_argument('--pin-test-disk-config',
                        help='Новый TOML: сохранить TEST_DISK_ID только после полной GET-сверки.')
    auth = token = username = password = client = None
    try:
        args = parser.parse_args(argv)
        if args.test_disk_config is not None:
            if args.expected_disk_id is not None or args.pin_test_disk_config is not None:
                raise ValidationError('Не смешивайте конфигурацию и первичную сверку.')
            args.expected_disk_id = load_test_disk_config(args.test_disk_config)
        if args.expected_disk_id is not None:
            validate_disk_id(args.expected_disk_id)
        if args.pin_test_disk_config is not None:
            if args.expected_disk_id is None:
                raise ValidationError('Сохранение требует явного UUID и полной проверки цели.')
            check_new_config_path(args.pin_test_disk_config)
        if not args.confirm_read_only:
            print(json.dumps({'mode': 'TEST_TARGET_PREVIEW', 'network_started': False,
                              'root_id': TEST_ROOT_ID, 'parent_id': TEST_PARENT_ID,
                              'max_auth_posts': 1, 'max_gets': 3, 'write_enabled': False,
                              'diagnose_metadata': args.diagnose_metadata,
                              'diagnose_responses': args.diagnose_responses,
                              'pin_requested': args.pin_test_disk_config is not None,
                              'expected_disk_provided': args.expected_disk_id is not None}))
            return 0
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            raise ValidationError('Нужен интерактивный терминал со скрытым вводом.')
        print('Разрешены один POST token и три GET метаданных. Запись документов запрещена.\n'
              'Подтвердите: ' + CONFIRMATION, file=sys.stderr)
        if input() != CONFIRMATION:
            raise ValidationError('Подтверждение read-only не получено.')
        login_transport = ReadOnlyHTTPSTransport(GatewayLoginPolicy(), confirmed=True)
        read_transport = ReadOnlyHTTPSTransport(TestTargetReadPolicy(), confirmed=True)
        auth = AuthSession(ApiSettings(AUTH_BASE, ('https://lk.sarex.io',)),
                           transport=login_transport, read_only_network_enabled=True,
                           diagnostics_enabled=args.diagnose_responses)
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            username = getpass.getpass('Login (скрытый ввод): ')
            password = getpass.getpass('Password (скрытый ввод): ')
        try:
            try:
                auth.login(username, password)
            except ApiError as exc:
                if args.diagnose_responses:
                    emit_stage('AUTH_TOKEN', auth, exc)
                raise
            if args.diagnose_responses:
                emit_stage('AUTH_TOKEN', auth)
            token = auth.access_token()
        finally:
            username = password = None
            auth.logout()  # Discard refresh immediately; no provider/refresh fallback for GETs.
        client = SarexClient(ApiSettings(DOCUMENTATION_BASE, ('https://api.sarex.io',)), token,
                             transport=read_transport, read_only_network_enabled=True,
                             diagnostics_enabled=args.diagnose_responses)
        if args.diagnose_responses:
            client = TargetResponseTrace(client)
        if args.diagnose_metadata:
            report, evidence = diagnose_target_result(client,
                                                       expected_disk_id=args.expected_disk_id)
            if args.pin_test_disk_config is not None:
                if evidence is not None:
                    save_verified_test_disk(args.pin_test_disk_config, evidence,
                                            args.expected_disk_id)
                report['test_disk_config_saved'] = evidence is not None
            print(json.dumps(report))
            return 0 if report['verified'] else 2
        evidence = inspect_target(client, expected_disk_id=args.expected_disk_id)
        summary = evidence.summary()
        if args.pin_test_disk_config is not None:
            save_verified_test_disk(args.pin_test_disk_config, evidence, args.expected_disk_id)
            summary['test_disk_config_saved'] = True
        print(json.dumps(summary))
        return 0
    except (ApiError, ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print('Read-only проверка прервана; автоматического повтора нет.', file=sys.stderr)
        return 130
    except Exception:
        print('Ошибка проверки тестовой папки; детали скрыты.', file=sys.stderr)
        return 1
    finally:
        if auth is not None:
            auth.logout()
        auth = token = username = password = client = None


if __name__ == '__main__':
    raise SystemExit(main())
