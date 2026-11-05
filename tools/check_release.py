"""Verify platform ZIP install/CLI in a fresh environment, synthetic inputs only."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from zipfile import ZipFile

from build_release import build


def execute_logged(output, name, args, **kwargs):
    completed = subprocess.run(args, capture_output=True, check=False, **kwargs)  # noqa: S603
    (output.parent / (name + '-stdout.txt')).write_bytes(completed.stdout)
    (output.parent / (name + '-stderr.txt')).write_bytes(completed.stderr)
    (output.parent / (name + '-exit.txt')).write_text(str(completed.returncode), encoding='utf-8')
    return completed


def check_load_blocked(output, python, cwd, account, *, configured=False):
    # Run the real CLI with no stdin. A regression must fail before contacting Sarex.
    script = """
import os
import runpy
import sys

def guard(event, args):
    if event.startswith(('socket.', 'urllib.')):
        raise RuntimeError('Network is prohibited during synthetic CLI validation')
    if event in ('os.mkdir', 'os.remove', 'os.rename', 'os.rmdir'):
        raise RuntimeError('File changes are prohibited during synthetic CLI validation')
    if event == 'open' and args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
        raise RuntimeError('File writes are prohibited during synthetic CLI validation')

sys.addaudithook(guard)
runpy.run_module('sarex_loader', run_name='__main__', alter_sys=True)
"""
    status, message = (
        (130, 'Работа прервана.') if configured
        else (2, 'Сначала выполните sarex-loader -setup.')
    )
    before = account.read_bytes() if account.exists() else None
    for profile in ('sk', 'vk'):
        completed = execute_logged(
            output, f'{output.stem}-load-{"configured" if configured else "clean"}-{profile}',
            [str(python), '-I', '-B', '-c', script, '-load', profile],
            cwd=cwd, env=os.environ | {'SAREX_ACCOUNT_FILE': str(account)},
            input=b'', timeout=30,
        )
        if (completed.returncode != status or message.encode() not in completed.stdout
                or completed.stderr):
            raise RuntimeError(f'Unexpected CLI response for -load {profile}; see CLI logs')
        after = account.read_bytes() if account.exists() else None
        if after != before:
            raise RuntimeError('Account changed during blocked CLI launch')


def run(output):
    output.parent.mkdir(parents=True, exist_ok=True)
    platform = 'windows' if os.name == 'nt' else 'macos'
    with tempfile.TemporaryDirectory(prefix='sarex-release-') as temporary:
        root = Path(temporary).resolve()
        archive = root / 'customer.zip'
        result = build(Path(__file__).resolve().parents[1], archive,
                       'v0.1.0-rc.6', platform=platform)
        with ZipFile(archive) as package:
            if package.testzip() is not None:
                raise RuntimeError('Corrupt release archive')
            package.extractall(root / 'extracted')
        extracted, = (root / 'extracted').iterdir()
        if os.name == 'nt':
            cmd = Path(os.environ['SystemRoot']) / 'System32' / 'cmd.exe'
            install_command = [str(cmd), '/d', '/c', 'start.bat', '-help']
        else:
            install_command = [sys.executable, 'start.py', '-help']
        completed = execute_logged(output, 'release-install',
            install_command, cwd=extracted, input=b'\r\n', timeout=180)
        if completed.returncode != 0 or b'-load sk' not in completed.stdout:
            raise RuntimeError('Clean release installation/CLI failed')
        python = extracted / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        check_load_blocked(output, python, extracted, extracted / 'account.toml')
        if os.name == 'nt':
            # Repeated launch must reuse the installed local Python, not the global launcher.
            marker = extracted / '.venv' / '.sarex-installed'
            installed = marker.stat().st_mtime_ns
            launched = execute_logged(output, 'release-bat',
                [str(cmd), '/d', '/c', 'start.bat', '-help'], cwd=extracted, input=b'\r\n',
                timeout=60)
            if (launched.returncode or b'-load sk' not in launched.stdout
                    or marker.stat().st_mtime_ns != installed):
                raise RuntimeError('Native BAT launcher failed; see release-bat-stderr.txt '
                                   'and release-bat-stdout.txt')
        delivered = output.parent / f'sarex-loader-v0.1.0-rc.6-{platform}.zip'
        with delivered.open('xb') as stream, archive.open('rb') as source:
            shutil.copyfileobj(source, stream)
        result = {k: v for k, v in result.items() if k != 'file'}
        result.update(clean_install=True, cli_help=True, production_load_requires_consent=True,
                      sarex_requests=0, native_upload_tested=False,
                      native_bat_install_and_repeat=os.name == 'nt')
        with output.open('x', encoding='utf-8') as stream:
            json.dump(result, stream, indent=2)
    print('Проверка установки из клиентского архива пройдена: ' + platform)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    run(parser.parse_args().output)
