"""Explicit recovery scope: local exports or opt-in tree reads; no credentials."""

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from sarex_loader.api_models import valid_id
from sarex_loader.config import RunConfig, checked_path, local_path, within_root
from sarex_loader.file_safety import read_snapshot
from sarex_loader.matching import validate_filename_numbers, validate_separator
from sarex_loader.name_check import validate_name
from sarex_loader.safety import ValidationError


@dataclass(frozen=True, repr=False)
class RecoveryConfig:
    root: Path
    registries: tuple[RunConfig, ...]
    folders: dict
    exports: tuple[dict, ...]
    separator: str
    numbers: dict
    limit: int
    url_contract_confirmed: bool
    tree: object = None
    routes: dict | None = None
    context_folders: dict | None = None


def parse_recovery_config(data: dict) -> RecoveryConfig:
    if type(data) is dict and data.get('mode') == 'tree-recovery':
        return _parse_tree_recovery(data)
    allowed = {'mode', 'input_root', 'registries', 'folders', 'exports', 'filename_separator',
               'filename_numbers', 'max_gateway_bytes', 'url_contract_confirmed'}
    if (type(data) is not dict or data.keys() - allowed
            or data.get('mode') != 'local-recovery'):
        raise ValidationError('Нужна отдельная конфигурация local-recovery.')
    try:
        root = checked_path(local_path(data['input_root']), directory=True)
        limit = data.get('max_gateway_bytes', 1024**2)
        if type(limit) is not int or not 1 <= limit <= 8 * 1024**2:
            raise ValueError
        separator = validate_separator(data['filename_separator'])
        registries = data['registries']
        if type(registries) is not list or not 1 <= len(registries) <= 3:
            raise ValueError
        configs = []
        for entry in registries:
            if type(entry) is not dict or set(entry) != {'excel', 'inspection_type'}:
                raise ValueError
            configs.append(RunConfig(command='audit', input_root=root, **entry))
        kinds = {c.inspection_type for c in configs}
        if len(kinds) != len(configs) or len({c.excel for c in configs}) != len(configs):
            raise ValueError
        numbers = data.get('filename_numbers', {})
        if type(numbers) is not dict or numbers.keys() - kinds:
            raise ValueError
        numbers = {k: validate_filename_numbers(numbers.get(k)) for k in kinds}
        folders, contexts = {}, set()
        entries = data['folders']
        if type(entries) is not list or not 1 <= len(entries) <= 1000:
            raise ValueError
        for entry in entries:
            if (type(entry) is not dict or set(entry) != {
                    'folder_id', 'inspection_type', 'office', 'contractor', 'month', 'verified'}
                    or entry['verified'] is not True or not valid_id(entry['folder_id'])
                    or entry['inspection_type'] not in kinds):
                raise ValueError
            for key in ('office', 'contractor'):
                validate_name(entry[key])
            if not isinstance(entry['month'], str) or not re.fullmatch(
                    r'[0-9]{4}-(0[1-9]|1[0-2])', entry['month']):
                raise ValueError
            context = tuple(entry[k] for k in ('inspection_type', 'office', 'contractor', 'month'))
            if entry['folder_id'] in folders or context in contexts:
                raise ValueError
            contexts.add(context)
            folders[entry['folder_id']] = context
        exports, paths = [], set()
        if type(data['exports']) is not list or not 1 <= len(data['exports']) <= 8:
            raise ValueError
        for entry in data['exports']:
            if type(entry) is not dict or set(entry) != {'path', 'sha256', 'folder_ids'}:
                raise ValueError
            path = within_root(entry['path'], root, directory=False)
            ids = entry['folder_ids']
            if (path.suffix.lower() != '.json' or path in paths
                    or type(ids) is not list or not ids or len(ids) > 1000
                    or any(not valid_id(i) or i not in folders for i in ids)
                    or len(set(ids)) != len(ids)
                    or not isinstance(entry['sha256'], str)
                    or not re.fullmatch('[0-9a-f]{64}', entry['sha256'])):
                raise ValueError
            paths.add(path)
            exports.append({'path': path, 'sha256': entry['sha256'], 'folder_ids': tuple(ids)})
        consent = data.get('url_contract_confirmed', False)
        if type(consent) is not bool:
            raise ValueError
        return RecoveryConfig(root, tuple(configs), folders, tuple(exports), separator,
                              numbers, limit, consent)
    except Exception:
        # Neither invalid paths nor TOML names/values are diagnostic output.
        raise ValidationError('Некорректная конфигурация локального восстановления.') from None


def load_recovery_config(path: str) -> RecoveryConfig:
    try:
        data = tomllib.loads(read_snapshot(local_path(path).absolute(), 65536).decode('utf-8'))
    except Exception:
        raise ValidationError('Не удалось прочитать конфигурацию восстановления.') from None
    return parse_recovery_config(data)


def _parse_tree_recovery(data):
    """Use the same rules as upload; no terminal IDs or per-month maps."""
    from sarex_loader.folder_resolver import FolderRules
    from sarex_loader.tree_source import parse_tree_source

    allowed = {'mode', 'input_root', 'registries', 'tree', 'filename_separator',
               'filename_numbers', 'url_contract_confirmed'}
    if data.keys() - allowed:
        raise ValidationError('TREE_RECOVERY_CONFIG_INVALID')
    try:
        root = checked_path(local_path(data['input_root']), directory=True)
        tree = parse_tree_source(data['tree'], root)
        separator = validate_separator(data['filename_separator'])
        entries = data['registries']
        if type(entries) is not list or not 1 <= len(entries) <= 3:
            raise ValueError
        configs, routes = [], {}
        for entry in entries:
            if type(entry) is not dict or entry.keys() - {
                    'excel', 'inspection_type', 'root_id', 'office_folders',
                    'contractor_folders', 'inspection_folder', 'folder_prefix', 'folder_routes'}:
                raise ValueError
            kind = entry['inspection_type']
            if kind in routes:
                raise ValueError
            prefix = entry.get('folder_prefix', [])
            if type(prefix) is not list:
                raise ValueError
            routes[kind] = FolderRules(entry['root_id'], entry['office_folders'],
                                       entry['contractor_folders'], entry.get('inspection_folder'),
                                       tuple(prefix), entry.get('folder_routes', ()))
            configs.append(RunConfig(command='audit', input_root=root, excel=entry['excel'],
                                     inspection_type=kind))
        if len({c.excel for c in configs}) != len(configs):
            raise ValueError
        numbers = data.get('filename_numbers', {})
        if type(numbers) is not dict or numbers.keys() - routes.keys():
            raise ValueError
        numbers = {kind: validate_filename_numbers(numbers.get(kind)) for kind in routes}
        consent = data.get('url_contract_confirmed', False)
        if type(consent) is not bool:
            raise ValueError
        return RecoveryConfig(root, tuple(configs), {}, (), separator, numbers,
                              tree.max_response_bytes, consent, tree, routes)
    except Exception:
        raise ValidationError(
            'TREE_RECOVERY_CONFIG_INVALID: проверьте правила и источники.') from None
