"""Prepare the customer environment, then run the same installed application on either OS."""

import hashlib
import os
import subprocess
import sys
from pathlib import Path


def source_hash(root):
    digest = hashlib.sha256()
    paths = [root / 'pyproject.toml', *sorted((root / 'src' / 'sarex_loader').glob('*.py')),
             root / 'src' / 'sarex_loader' / 'profile-routes.toml',
             root / 'src' / 'sarex_loader' / 'browser_extension.js']
    for path in paths:
        digest.update(path.relative_to(root).as_posix().encode('utf-8') + b'\0')
        digest.update(path.read_bytes())
    return digest.hexdigest()


def prepare(root):
    environment = root / '.venv'
    python = environment / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    marker = environment / '.sarex-installed'
    if environment.is_symlink() or marker.is_symlink():
        raise OSError('Небезопасная ссылка вместо локального окружения.')
    expected = source_hash(root)
    created = not python.is_file()
    if created:
        print('Подготовка локального окружения Python…', flush=True)
        subprocess.run([sys.executable, '-m', 'venv', str(environment)], check=True)  # noqa: S603
    if created or not marker.is_file() or marker.read_text(encoding='ascii').strip() != expected:
        print('Установка программы и зависимостей. При первом запуске нужен интернет…', flush=True)
        subprocess.run([str(python), '-m', 'pip', '--disable-pip-version-check',  # noqa: S603
                        'install', str(root)], check=True)
        marker.write_text(expected + '\n', encoding='ascii')
    return python


def main(argv=None):
    # This standalone entry point also runs before package installation on older Python.
    if sys.version_info < (3, 11):  # noqa: UP036
        print('Нужен Python 3.11 или новее. Установите Python и запустите программу снова.')
        return 2
    try:
        root = Path(__file__).resolve().parent
        python = prepare(root)
        environment = dict(os.environ)
        environment['SAREX_ACCOUNT_FILE'] = str(root / 'account.toml')
        return subprocess.run([str(python), '-m', 'sarex_loader.customer_start',  # noqa: S603
                               *(sys.argv[1:] if argv is None else argv)],
                              env=environment, check=False).returncode
    except (OSError, subprocess.SubprocessError, UnicodeError):
        print('Не удалось подготовить программу. Проверьте Python, доступ к папке и интернет; '
              'затем повторите запуск. Входные документы не изменялись.')
        return 2
    except KeyboardInterrupt:
        print('Подготовка прервана. Можно повторить запуск.')
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
