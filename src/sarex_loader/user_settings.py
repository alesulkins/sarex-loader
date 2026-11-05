"""Local or explicitly distributed account. Secrets never enter plans or reports."""

import csv
import getpass
import io
import json
import os
import re
import stat
import subprocess
import tomllib
import warnings
from dataclasses import dataclass, replace
from pathlib import Path
from uuid import uuid4

from sarex_loader.config import checked_path, local_path
from sarex_loader.file_safety import directory_fd, read_snapshot
from sarex_loader.recursive_gateway import PROFILE_ROOTS
from sarex_loader.safety import ValidationError


@dataclass(frozen=True, repr=False)
class UserSettings:
    username: str
    password: str
    allow_folder_creation: bool = False
    results_dir: str | None = None


def settings_path():
    # Only paths are read from environment, never passwords/tokens.
    if account := distribution_account_path():
        return account
    # LOCALAPPDATA selects a local directory only.
    if os.name == 'nt':
        base = os.environ.get('LOCALAPPDATA')
        if not base:
            raise ValidationError('Не определена локальная папка настроек Windows.')
        return local_path(base) / 'SarexLoader' / 'settings.toml'
    return Path.home() / '.config' / 'sarex-loader' / 'settings.toml'


def distribution_account_path():
    if value := os.environ.get('SAREX_ACCOUNT_FILE'):
        return local_path(value)
    # Direct short commands from the extracted project use the same account as start.py.
    root = Path.cwd()
    if (root / 'start.py').is_file() and (root / 'customer.routes.toml').is_file():
        return root / 'account.toml'
    return None


def _distribution_path(path):
    value = distribution_account_path()
    return bool(value and value.absolute() == path.absolute())


def settings_configured(path=None):
    """An empty shipped account prompts setup; malformed/nonempty files fail closed."""
    path = local_path(path or settings_path())
    if not path.exists():
        return False
    if _distribution_path(path):
        try:
            data = tomllib.loads(read_snapshot(path, 65536).decode('utf-8'))
        except (ValueError, UnicodeError):
            raise ValidationError('Не удалось прочитать конфигурацию учётной записи.') from None
        if data.get('auth') == {'login': '', 'password': ''}:
            return False
    return True


def root_id_from_url(profile, url):
    if profile not in PROFILE_ROOTS or not isinstance(url, str):
        raise ValidationError('Выберите профиль sk (СК) или vk (ВК).')
    root = PROFILE_ROOTS[profile][0]
    if url != f'https://lk.sarex.io/documentations/{root}':
        raise ValidationError('Ссылка Sarex не соответствует выбранному профилю СК/ВК.')
    return root


def load_settings(path=None):
    path = checked_path(local_path(path or settings_path()), directory=False)
    try:
        if os.name != 'nt' and not _distribution_path(path):
            for item in (path.parent, path):
                info = item.lstat()
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                    raise ValidationError('Настройки доступны другим пользователям. '
                                          'Запустите -setup.')
        data = tomllib.loads(read_snapshot(path, 65536).decode('utf-8'))
        if (set(data) - {'version', 'allow_folder_creation', 'auth', 'profiles', 'results_dir'}
                or not {'version', 'allow_folder_creation', 'auth', 'profiles'} <= set(data)
                or data['version'] != 1 or type(data['allow_folder_creation']) is not bool
                or set(data['auth']) != {'login', 'password'}
                or set(data['profiles']) != set(PROFILE_ROOTS)):
            raise ValueError
        for profile in PROFILE_ROOTS:
            if set(data['profiles'][profile]) != {'root_url'}:
                raise ValueError
            root_id_from_url(profile, data['profiles'][profile]['root_url'])
        username, password = data['auth']['login'], data['auth']['password']
        if any(type(v) is not str or not 1 <= len(v) <= 4096 for v in (username, password)):
            raise ValueError
        results = data.get('results_dir')
        if results is not None:
            if type(results) is not str or not results.strip():
                raise ValueError
            if not local_path(results).is_absolute():
                raise ValueError
        return UserSettings(username, password, data['allow_folder_creation'], results)
    except (ValueError, KeyError, TypeError, UnicodeError):
        raise ValidationError('Некорректный файл настроек. '
                              'Выполните sarex-loader -setup.') from None


def _windows_private_folder(path):
    """Use a Windows SID, not a localized or environment-supplied account name."""
    system = Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32'
    result = subprocess.run(  # noqa: S603 — fixed Windows utility, no shell or secret arguments
        [str(system / 'whoami.exe'), '/user', '/fo', 'csv', '/nh'],
        capture_output=True, check=True, timeout=10)
    rows = list(csv.reader(io.StringIO(result.stdout.decode('utf-8', errors='replace'))))
    sid = rows[0][-1] if len(rows) == 1 else ''
    if not re.fullmatch(r'S-1-[0-9-]+', sid):
        raise ValidationError('Не удалось установить приватные права настроек Windows.')
    subprocess.run(  # noqa: S603 — validated SID, fixed utility, shell=False
        [str(system / 'icacls.exe'), str(path), '/inheritance:r',
         '/grant:r', f'*{sid}:(OI)(CI)F'], capture_output=True, check=True, timeout=10)


def save_settings(settings, path=None):
    path = local_path(path or settings_path()).absolute()
    # Only this dedicated configuration directory is created or permissioned.
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    checked_path(path.parent, directory=True)
    if path.is_symlink():
        raise ValidationError('Настройки не могут быть символической ссылкой.')
    if os.name == 'nt' and not _distribution_path(path):
        try:
            _windows_private_folder(path.parent)
        except (OSError, subprocess.SubprocessError):
            raise ValidationError('Не удалось ограничить доступ к настройкам Windows; '
                                  'пароль не сохранён.') from None
    elif os.name != 'nt' and not _distribution_path(path):
        if path.parent.stat().st_uid != os.getuid():
            raise ValidationError('Папка настроек принадлежит другому пользователю.')
        path.parent.chmod(0o700)
    # JSON quoting is also valid TOML basic-string quoting; it is never shell text.
    def quote(value):
        return json.dumps(value, ensure_ascii=False)
    raw = ('# Учётная запись Sarex. Пароль не выводить в логи и отчёты.\n'
           'version = 1\nallow_folder_creation = '
           + str(settings.allow_folder_creation).lower()
           + ('\nresults_dir = ' + quote(settings.results_dir) if settings.results_dir else '')
           + '\n\n[auth]\nlogin = ' + quote(settings.username)
           + '\npassword = ' + quote(settings.password) + '\n')
    for kind, (root, _) in PROFILE_ROOTS.items():
        raw += f'\n[profiles.{kind}]\nroot_url = "https://lk.sarex.io/documentations/{root}"\n'
    temp = '.settings-' + uuid4().hex + '.toml'
    try:
        if os.name == 'nt':
            from sarex_loader.windows_files import _handle, locked_directory

            with locked_directory(path.parent):
                fd = _handle(path.parent / temp, create=True)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw.encode('utf-8'))
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(path.parent / temp, path)
        else:
            with directory_fd(path.parent) as parent:
                fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw.encode('utf-8'))
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp, path.name, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
    except (OSError, subprocess.SubprocessError):
        raise ValidationError('Не удалось безопасно сохранить настройки; '
                              'секреты не выводятся.') from None
    finally:
        raw = None
    return path


def setup(*, ask=input, password_reader=getpass.getpass, path=None):
    username = password = None
    try:
        username = ask('Логин Sarex: ')
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            password = password_reader('Пароль Sarex (скрытый ввод): ')
        if any(not v or len(v) > 4096 for v in (username, password)):
            raise ValidationError('Логин и пароль должны быть непустыми.')
        print('Создание папок отключено в текущей поставке: allow_folder_creation = false.')
        previous_results = load_settings(path).results_dir if settings_configured(path) else None
        result = save_settings(UserSettings(username, password, results_dir=previous_results), path)
        print('Настройки сохранены локально. Повторный -setup позволяет изменить учётную запись.')
        print('Файл настроек: ' + str(result))
    except getpass.GetPassWarning:
        raise ValidationError('Скрытый ввод недоступен; запустите обычный терминал.') from None
    finally:
        username = password = None


def require_settings(path=None):
    if not settings_configured(path):
        raise ValidationError('Сначала выполните sarex-loader -setup.')
    return load_settings(path)


def folder_setting(action, *, path=None):
    """Local switch only: no auth, GET, folder creation or secret output."""
    if action not in {'on', 'off', 'status'}:
        raise ValidationError('Используйте -folders on, -folders off или -folders status.')
    if action == 'status' and not settings_configured(path):
        print('Создание месячных папок: выключено (по умолчанию).')
        return
    settings = require_settings(path)
    if action != 'status':
        settings = replace(settings, allow_folder_creation=action == 'on')
        save_settings(settings, path)
    print('Создание месячных папок: ' + ('включено.' if settings.allow_folder_creation
                                       else 'выключено.'))
    if settings.allow_folder_creation:
        print('Только при -load sk/vk и отдельном подтверждении списка. '
              'Preview, dry-run и fill ничего в Sarex не создают.')
