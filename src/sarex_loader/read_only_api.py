"""Separate manual entry point. Preview by default; no link to upload/fill-urls."""

import getpass
import hashlib
import json
import sys
import warnings

from sarex_loader.api_client import ApiSettings, SarexClient
from sarex_loader.api_models import ApiError
from sarex_loader.auth import AuthSession
from sarex_loader.children import summarize_children
from sarex_loader.cli import SafeParser
from sarex_loader.https_transport import ReadOnlyHTTPSTransport
from sarex_loader.name_check import (
    check_document_name,
    check_name_digest,
    validate_name,
    validate_name_digest,
)
from sarex_loader.read_only_policy import AUTH_BASE, DOCUMENTATION_BASE, load_read_only_policy
from sarex_loader.safety import ValidationError


def _expected_name() -> str:
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValidationError('Скрытый ввод ожидаемого имени требует интерактивного терминала.')
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        return validate_name(getpass.getpass('Ожидаемое точное имя (скрытый ввод): '))


def main(argv=None):
    parser = SafeParser(description='Read-only API: сначала локальная проверка конфигурации.')
    parser.add_argument('--config', required=True)
    parser.add_argument('--operation', choices=('document', 'ancestors', 'types'),
                        default='document')
    parser.add_argument('--document-id', type=int)
    parser.add_argument('--confirm-read-only', action='store_true')
    parser.add_argument('--check-name', action='store_true',
                        help='Скрыто ввести имя для сравнения.')
    parser.add_argument('--name-sha256', help='Проверить полученный ранее хеш полностью офлайн.')
    parser.add_argument('--list-children', action='store_true',
                        help='Показать количества и до 20 ID files/folders одной папки.')
    auth = None
    expected_name = None
    try:
        args = parser.parse_args(argv)
        if args.list_children and (args.operation != 'document' or args.check_name
                                   or args.name_sha256 is not None):
            raise ValidationError('Список детей — отдельный режим document без проверки имени.')
        if (args.check_name and args.operation != 'document'
                or args.name_sha256 is not None
                and (not args.check_name or args.confirm_read_only)):
            raise ValidationError(
                'Проверка имени — только document; проверка хеша не допускает сеть.')
        policy = load_read_only_policy(args.config)
        identifier = args.document_id
        if args.operation == 'types':
            if identifier is not None:
                raise ValidationError('Для types document-id не используется.')
            url = DOCUMENTATION_BASE + '/v1/documents/types'
        else:
            if identifier not in policy.document_ids:
                raise ValidationError('Нужен document-id из явного разрешённого списка.')
            url = DOCUMENTATION_BASE + f'/v1/documents/{identifier}'
            if args.operation == 'ancestors':
                url += '/ancestors'
        policy.authorize('GET', url)
        if args.name_sha256 is not None:
            validate_name_digest(args.name_sha256)
            expected_name = _expected_name()
            result = check_name_digest(identifier, args.name_sha256, expected_name)
            print(json.dumps(result))
            return 0 if result['status'] == 'MATCH' else 3
        # Comparison output is exactly one result; retain preview for nonexecuting runs.
        operation = 'children' if args.list_children else args.operation
        if not ((args.check_name or args.list_children) and args.confirm_read_only):
            print(json.dumps({'mode': 'READ_ONLY_PREVIEW', 'network_started': False,
                              'operation': operation, 'document_id': identifier,
                              'auth_endpoint': AUTH_BASE + '/token/', 'get_endpoint': url,
                              'document_writes_allowed': False}))
        if not args.confirm_read_only:
            return 0
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            raise ValidationError('Ручной запуск требует интерактивного терминала.')
        phrase = f'READ ONLY {operation} {identifier if identifier is not None else "types"}'
        print('Только после отдельного разрешения. Будут POST token и один указанный GET.\n'
              'Для подтверждения введите: ' + phrase, file=sys.stderr)
        if input().strip() != phrase:
            raise ValidationError('Подтверждение read-only режима не получено.')
        if args.check_name:
            # Validate before credentials, DNS or a request; invalid input cannot cause auth.
            expected_name = _expected_name()
        transport = ReadOnlyHTTPSTransport(policy, confirmed=True)
        auth = AuthSession(ApiSettings(AUTH_BASE, ('https://lk.sarex.io',),
                                        timeouts=policy.timeouts,
                                        max_response_bytes=policy.max_response_bytes),
                           transport=transport, read_only_network_enabled=True)
        with warnings.catch_warnings():
            # No getpass fallback that could echo a password when /dev/tty is unavailable.
            warnings.simplefilter('error', getpass.GetPassWarning)
            username = getpass.getpass('Login (скрытый ввод): ')
            password = getpass.getpass('Password (скрытый ввод): ')
        try:
            auth.login(username, password)
        finally:
            username = password = None  # Release references; not a claim of memory zeroization.
        client = SarexClient(ApiSettings(DOCUMENTATION_BASE, ('https://api.sarex.io',),
                                         timeouts=policy.timeouts,
                                         max_response_bytes=policy.max_response_bytes),
                             token_provider=auth.access_token, transport=transport,
                             read_only_network_enabled=True)
        if args.operation == 'document':
            document = client.get_document(identifier)
            if args.list_children:
                print(json.dumps(summarize_children(document)))
                return 0
            if args.check_name:
                result = check_document_name(document, expected_name)
                print(json.dumps(result))
                return 0 if result['status'] == 'MATCH' else 3
            result = {'id': document.id, 'is_folder': document.is_folder,
                      'name_sha256': hashlib.sha256(document.name.encode()).hexdigest()}
        elif args.operation == 'ancestors':
            result = {'ancestors_count': len(client.get_ancestors(identifier))}
        else:
            result = {'types_count': len(client.get_document_types())}
        print(json.dumps({'status': 'READ_ONLY_RESPONSE_VALIDATED', **result,
                          'api_id_url_relationship_verified': False}))
        return 0
    except (ValidationError, ApiError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print('Ручная проверка прервана; повторы не выполнялись.', file=sys.stderr)
        return 130
    except Exception:
        print('Ошибка read-only проверки; детали скрыты, повторы не выполнялись.', file=sys.stderr)
        return 1
    finally:
        expected_name = None  # Release our reference, not a guarantee of memory zeroization.
        if auth is not None:
            auth.logout()


if __name__ == '__main__':
    raise SystemExit(main())
