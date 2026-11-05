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


def run(output):
    output.parent.mkdir(parents=True, exist_ok=True)
    platform = 'windows' if os.name == 'nt' else 'macos'
    with tempfile.TemporaryDirectory(prefix='sarex-release-') as temporary:
        root = Path(temporary)
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
        if completed.returncode != 0:
            raise RuntimeError('Clean release installation/CLI failed')
        python = extracted / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        for profile in ('sk', 'vk'):
            blocked = subprocess.run(  # noqa: S603
                [str(python), '-m', 'sarex_loader', '-load', profile], cwd=extracted,
                capture_output=True, input=b'', timeout=30, check=False)
            if blocked.returncode != 130:
                raise RuntimeError('Production load must require input and explicit consent')
        if os.name == 'nt':
            # Repeated launch must reuse the installed local Python, not the global launcher.
            launched = execute_logged(output, 'release-bat',
                [str(cmd), '/d', '/c', 'start.bat', '-help'], cwd=extracted, input=b'\r\n',
                timeout=60)
            if launched.returncode:
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
