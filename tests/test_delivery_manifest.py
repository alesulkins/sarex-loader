"""Validate real customer archives, including lazy imports and safety components."""

import ast
import importlib.util
import tomllib
from pathlib import Path
from zipfile import ZipFile

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('delivery_builder', ROOT / 'tools/build_release.py')
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


def local_imports(source, modules):
    dependencies = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            dependencies.update(alias.name.split('.')[1] for alias in node.names
                                if alias.name.startswith('sarex_loader.'))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ''
            if module.startswith('sarex_loader.'):
                dependencies.add(module.split('.')[1])
            elif module == 'sarex_loader' or node.level:
                dependencies.update(alias.name for alias in node.names if alias.name in modules)
    return dependencies


@pytest.mark.parametrize('platform', ['windows', 'macos', 'linux'])
def test_customer_archive_preserves_commands_and_dependencies(tmp_path, platform):
    archive = tmp_path / 'customer.zip'
    result = BUILDER.build(ROOT, archive, BUILDER.RELEASE_VERSION, platform=platform)
    assert result['account_included_from_workspace'] is False
    with ZipFile(archive) as package:
        assert package.testzip() is None
        prefix = f'sarex-loader-{BUILDER.RELEASE_VERSION}-{platform}/'
        files = {name.removeprefix(prefix): package.read(name) for name in package.namelist()}
    assert all(not name.startswith(('tests/', 'docs/', 'outputs/', '.git/', '.venv/'))
               for name in files)
    assert not any(name.endswith(('.sqlite', '.xlsx', '.pdf', '.log')) for name in files)
    account = tomllib.loads(files['account.toml'].decode())
    assert account['auth'] == {'login': '', 'password': ''}
    assert account['allow_folder_creation'] is False
    assert ('start.bat' in files) == (platform == 'windows')
    assert ('start.command' in files) == (platform == 'macos')
    if platform == 'windows':
        assert b'\r\n' in files['start.bat']
        assert b'\n' not in files['start.bat'].replace(b'\r\n', b'')
    modules = {Path(name).stem for name in files
               if name.startswith('src/sarex_loader/') and name.endswith('.py')}
    assert {'customer_launcher', 'customer_start', 'customer_test', 'customer_test_scope',
            'acceptance_upload', 'production_upload', 'upload_preview', 'recovery',
            'folder_creation', 'monthly_folders', 'journal', 'windows_journal',
            'windows_files', 'multipart', 'recursive_gateway'} <= modules
    assert modules.isdisjoint(BUILDER.DEVELOPER_MODULES)
    all_modules = {path.stem for path in (ROOT / 'src/sarex_loader').glob('*.py')}
    for name, content in files.items():
        if name.endswith('.py'):
            missing = local_imports(content.decode('utf-8'), all_modules) - modules
            assert not missing, (name, missing)
    for name in BUILDER.DEVELOPER_MODULES:
        assert (ROOT / 'src/sarex_loader' / (name + '.py')).is_file()


def test_release_version_matches_package():
    version = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']['version']
    assert BUILDER.RELEASE_VERSION == 'v' + version.replace('rc', '-rc.')
