"""Reproduce redirected Windows cp1252 on any OS, without authentication/network."""

import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize('module', [
    'sarex_loader', 'sarex_loader.customer_launcher', 'sarex_loader.customer_start'])
@pytest.mark.parametrize('encoding', ['cp1252', 'ascii', 'utf-8'])
def test_russian_help_with_redirected_output(module, encoding, tmp_path):
    env = dict(os.environ, PYTHONIOENCODING=encoding, PYTHONUTF8='0')
    env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1] / 'src')
    result = subprocess.run(  # noqa: S603
        [sys.executable, '-m', module, '-help'], cwd=tmp_path,
        env=env, capture_output=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    assert 'Справка' in result.stdout.decode('utf-8') or 'справка' in result.stdout.decode('utf-8')
    assert b'UnicodeEncodeError' not in result.stderr


def test_test_pdf_routes_to_safe_argument_validation(tmp_path):
    env = dict(os.environ, PYTHONIOENCODING='cp1252', PYTHONUTF8='0')
    env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1] / 'src')
    result = subprocess.run(  # noqa: S603
        [sys.executable, '-m', 'sarex_loader', '-test-pdf', '--invalid'],
        env=env, cwd=tmp_path, capture_output=True, timeout=30, check=False)
    assert result.returncode == 2
    assert 'Команда: -test-pdf' in result.stdout.decode('utf-8')
    assert b'Traceback' not in result.stderr


def test_bootstrap_error_is_readable_in_cp1252(tmp_path):
    launcher = Path(__file__).resolve().parents[1] / 'start.py'
    script = ('import runpy,sys; module=runpy.run_path(sys.argv[1]); '
              'sys.version_info=(3,10); raise SystemExit(module["main"]([]))')
    result = subprocess.run(  # noqa: S603
        [sys.executable, '-c', script, str(launcher)], cwd=tmp_path,
        env=dict(os.environ, PYTHONIOENCODING='cp1252', PYTHONUTF8='0'),
        capture_output=True, timeout=30, check=False)
    assert result.returncode == 2
    assert 'Нужен Python' in result.stdout.decode('utf-8')
    assert b'Traceback' not in result.stderr


def test_load_dry_run_uses_only_preview(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from sarex_loader import customer_launcher as launcher

    calls = []
    monkeypatch.setattr(launcher, 'require_settings', lambda: SimpleNamespace(results_dir=None))
    monkeypatch.setattr(launcher, 'collect_inputs',
                        lambda command, profile: calls.append(('inputs', command, profile)) or {})
    monkeypatch.setattr(launcher, 'run_profile',
                        lambda command, profile, **kwargs: calls.append(('run', command, profile)))
    for profile in ('sk', 'vk'):
        assert launcher.main(['-load', profile, '--dry-run']) == 0
        assert calls[-2:] == [('inputs', 'preview', profile), ('run', 'preview', profile)]


def test_fill_dry_run_is_rejected_before_authorization(monkeypatch):
    from sarex_loader import customer_launcher as launcher

    def forbidden():
        raise AssertionError('Invalid command must not authorize')

    monkeypatch.setattr(launcher, 'require_settings', forbidden)
    assert launcher.main(['-fill', 'sk', '--dry-run']) == 2
