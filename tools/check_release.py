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


def run(output):
    platform = 'windows' if os.name == 'nt' else 'macos'
    with tempfile.TemporaryDirectory(prefix='sarex-release-') as temporary:
        root = Path(temporary)
        archive = root / 'customer.zip'
        result = build(Path(__file__).resolve().parents[1], archive,
                       'v0.1.0-rc.3', platform=platform)
        with ZipFile(archive) as package:
            if package.testzip() is not None:
                raise RuntimeError('Corrupt release archive')
            package.extractall(root / 'extracted')
        extracted, = (root / 'extracted').iterdir()
        completed = subprocess.run(  # noqa: S603
            [sys.executable, 'start.py', '-help'], cwd=extracted,
            capture_output=True, timeout=180, check=False)
        if completed.returncode != 0:
            raise RuntimeError('Clean release installation/CLI failed')
        python = extracted / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        for profile in ('sk', 'vk'):
            blocked = subprocess.run(  # noqa: S603
                [str(python), '-m', 'sarex_loader', '-load', profile], cwd=extracted,
                capture_output=True, timeout=30, check=False)
            if blocked.returncode != 2:
                raise RuntimeError('Production load must remain blocked')
        if os.name == 'nt':
            # Feed Enter to the launcher's pause; no interactive credentials are requested.
            cmd = Path(os.environ['SystemRoot']) / 'System32' / 'cmd.exe'
            launched = subprocess.run(  # noqa: S603 — fixed shipped launcher, no user input
                [str(cmd), '/d', '/c', 'start.bat', '-help'], cwd=extracted, input=b'\r\n',
                capture_output=True, timeout=60, check=False)
            if launched.returncode:
                raise RuntimeError('Native BAT launcher failed')
        delivered = output.parent / f'sarex-loader-v0.1.0-rc.3-{platform}.zip'
        with delivered.open('xb') as stream, archive.open('rb') as source:
            shutil.copyfileobj(source, stream)
        result = {k: v for k, v in result.items() if k != 'file'}
        result.update(clean_install=True, cli_help=True, production_load_blocked=True,
                      sarex_requests=0, native_upload_tested=False)
        with output.open('x', encoding='utf-8') as stream:
            json.dump(result, stream, indent=2)
    print('Проверка установки из клиентского архива пройдена: ' + platform)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    run(parser.parse_args().output)
