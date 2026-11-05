"""Opt-in token response field inspection: one POST, no session tokens or subsequent GET."""

import getpass
import json
import sys
import warnings

from sarex_loader.api_client import ApiSettings
from sarex_loader.api_models import ApiError
from sarex_loader.auth import AuthSession
from sarex_loader.cli import SafeParser
from sarex_loader.gateway_diagnostic_policy import GATEWAY_LOGIN_URL, GatewayLoginPolicy
from sarex_loader.https_transport import ReadOnlyHTTPSTransport
from sarex_loader.safety import ValidationError

CONFIRMATION = 'TOKEN RESPONSE FIELD NAMES'


def main(argv=None):
    parser = SafeParser(
        description='Только имена полей token-ответа; preview без сети по умолчанию.')
    parser.add_argument('--confirm-token-fields', action='store_true')
    username = password = auth = None
    try:
        args = parser.parse_args(argv)
        if not args.confirm_token_fields:
            print(json.dumps({'mode': 'TOKEN_FIELDS_PREVIEW', 'network_started': False,
                              'method': 'POST', 'url': GATEWAY_LOGIN_URL, 'max_requests': 1}))
            return 0
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            raise ValidationError('Диагностика требует интерактивного терминала.')
        print('Только после отдельного разрешения: один POST авторизации, без Gateway.\n'
              + GATEWAY_LOGIN_URL + '\nВведите: ' + CONFIRMATION, file=sys.stderr)
        if input() != CONFIRMATION:
            raise ValidationError('Подтверждение диагностики полей не получено.')
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            username = getpass.getpass('Login (скрытый ввод): ')
            password = getpass.getpass('Password (скрытый ввод): ')
        policy = GatewayLoginPolicy()
        auth = AuthSession(
            ApiSettings('https://lk.sarex.io/api', ('https://lk.sarex.io',),
                        timeouts=policy.timeouts, max_response_bytes=policy.max_response_bytes),
            transport=ReadOnlyHTTPSTransport(policy, confirmed=True),
            read_only_network_enabled=True,
        )
        fields = auth.inspect_login_fields(username, password)
        username = password = None
        print(json.dumps(fields))
        return 0
    except (ValidationError, ApiError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print('Диагностика прервана; повторов нет.', file=sys.stderr)
        return 130
    except Exception:
        print('Ошибка диагностики; детали скрыты, повторов нет.', file=sys.stderr)
        return 1
    finally:
        username = password = None
        if auth is not None:
            auth.logout()


if __name__ == '__main__':
    raise SystemExit(main())
