"""Shared bounded tree sources: private JSON exports or opt-in browser reads."""

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime

from sarex_loader.api_models import ApiError, ApiErrorCode, decode_payload, valid_id
from sarex_loader.config import within_root
from sarex_loader.file_safety import read_snapshot
from sarex_loader.folder_resolver import FolderResolution, FolderResolver
from sarex_loader.gateway_models import MAX_GATEWAY_NODES, parse_gateway_search_documents
from sarex_loader.safety import ValidationError


@dataclass(frozen=True, repr=False)
class TreeSource:
    source: str
    disk_id: str
    exports: tuple = ()
    max_response_bytes: int = 8 * 1024**2
    max_folders: int = 2000
    # Explicitly observed GET scopes for a local snapshot. None preserves legacy
    # imports; an empty tuple explicitly declares that no file lists were read.
    queried_folder_ids: tuple | None = None
    browser_mode: str = 'isolated'
    root_ids: tuple = ()
    traversal: str = 'required'

    def verify_sources(self):
        for path, digest in self.exports:
            if hashlib.sha256(read_snapshot(path, self.max_response_bytes)).hexdigest() != digest:
                raise ValidationError('TREE_SOURCE_CHANGED: нужен новый просмотр плана.')


def parse_tree_source(value, root):
    if (type(value) is not dict or value.keys() - {
            'source', 'disk_id', 'exports', 'max_response_bytes', 'max_folders',
            'queried_folder_ids', 'browser_mode', 'root_ids', 'traversal'}
            or value.get('source') not in {'json', 'browser', 'gateway'}
            or type(value.get('disk_id')) is not str
            or re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',
                            value['disk_id']) is None):
        raise ValidationError('TREE_CONFIG_INVALID: нужны source и точный disk_id.')
    limit = value.get('max_response_bytes', 8 * 1024**2)
    budget = value.get('max_folders', 2000)
    if (type(limit) is not int or not 1 <= limit <= 8 * 1024**2
            or type(budget) is not int or not 1 <= budget <= 10000):
        raise ValidationError('TREE_CONFIG_INVALID: неверные лимиты.')
    exports = value.get('exports', [])
    mode = value.get('browser_mode', 'isolated')
    roots = value.get('root_ids', [])
    traversal = value.get('traversal', 'required')
    if (type(roots) is not list or traversal not in ('required', 'recursive')
            or traversal == 'recursive' and (value['source'] != 'gateway' or len(roots) != 1)):
        raise ValidationError('TREE_CONFIG_INVALID: рекурсивный Gateway требует один корень.')
    if (type(mode) is not str or mode not in {'isolated', 'extension'} or type(roots) is not list
            or len(roots) > 16 or any(not valid_id(i) for i in roots)
            or len(set(roots)) != len(roots)
            or (value['source'] == 'browser' and (mode == 'extension') != bool(roots))
            or (value['source'] == 'json' and ('browser_mode' in value or 'root_ids' in value))
            or (value['source'] == 'gateway' and ('browser_mode' in value or not roots))):
        raise ValidationError('TREE_CONFIG_INVALID: gateway/extension требуют явные root_ids.')
    if value['source'] == 'gateway':
        from sarex_loader.gateway_tree_policy import GatewayTreeReadPolicy

        GatewayTreeReadPolicy(value['disk_id'], roots[0], limit)
    scopes = value.get('queried_folder_ids')
    if 'queried_folder_ids' in value and (
            value['source'] != 'json' or type(scopes) is not list or len(scopes) > 10000
            or any(not valid_id(i) for i in scopes) or len(set(scopes)) != len(scopes)):
        raise ValidationError('TREE_CONFIG_INVALID: неверные области чтения JSON.')
    if (type(exports) is not list or len(exports) > 256
            or (value['source'] == 'json') != bool(exports)):
        raise ValidationError('TREE_CONFIG_INVALID: JSON требует exports, browser их запрещает.')
    result, seen = [], set()
    for entry in exports:
        if (type(entry) is not dict or set(entry) != {'path', 'sha256'}
                or type(entry['sha256']) is not str
                or re.fullmatch('[0-9a-f]{64}', entry['sha256']) is None):
            raise ValidationError('TREE_CONFIG_INVALID: нужны path и SHA256 каждой выгрузки.')
        path = within_root(entry['path'], root, directory=False)
        if path.suffix.lower() != '.json' or path in seen:
            raise ValidationError('TREE_CONFIG_INVALID: повтор или неверный тип файла.')
        result.append((path, entry['sha256']))
        seen.add(path)
    return TreeSource(value['source'], value['disk_id'], tuple(result), limit, budget,
                      tuple(scopes) if scopes is not None else None, mode, tuple(roots), traversal)


def add_response(index, raw, limit, *, queried_folder=None):
    # The existing parser is the single authority for untrusted IDs, paths and names.
    from sarex_loader.recovery import _pagination

    try:
        parsed = parse_gateway_search_documents(raw, max_response_bytes=limit)
        envelope = decode_payload(raw, max_nodes=MAX_GATEWAY_NODES)
    except ApiError:
        raise ValidationError('TREE_RESPONSE_INVALID: ответ Gateway отклонён.') from None
    pagination = _pagination(envelope, len(parsed.documents))
    if any(k in envelope for k in ('has_next', 'next_page', 'pagination')):
        # No verified contract for these alternate paging mechanisms. Do not drop
        # their presence while projecting the browser response.
        raise ValidationError('TREE_PAGINATION_UNSUPPORTED: неизвестная схема страниц.')
    # Never follow an unverified `next` URL or invent offset/limit parameters.
    if pagination['more_pages_hint'] or any(
            envelope.get(k, 0) > len(parsed.documents) for k in ('count', 'total')):
        raise ValidationError('TREE_PAGINATION_UNSUPPORTED: ответ требует дополнительных страниц.')
    if queried_folder is not None:
        direct = {d.id for d in parsed.documents
                  if len(d.path_ids) > 1 and d.path_ids[-2] == queried_folder}
        if set(index.children.get(queried_folder, {})) - direct:
            raise ValidationError('TREE_SNAPSHOT_CHANGED: ранее видимые дети исчезли из ответа.')
    index.add(parsed.documents)
    if queried_folder is not None:
        d = index.documents.get(queried_folder)
        if (d is None or not d.is_folder
                or not any(item.id == queried_folder for item in parsed.documents)):
            raise ValidationError('TREE_REQUEST_SCOPE_UNVERIFIED: нет запрошенной папки.')
        index.queried_folders.add(queried_folder)
    index.metadata.append(pagination)
    index.source_hashes.append(hashlib.sha256(raw).hexdigest())


def read_tree(source, paths, *, allow_browser=False, checkpoint=None, progress=None):
    """paths is a set of (root ID, exact folder components), independent of row count."""
    if type(allow_browser) is not bool:
        raise ValidationError('TREE_READ_MODE_INVALID')
    index = FolderResolver()
    if source.source == 'gateway':
        if not allow_browser:
            raise ValidationError('TREE_READ_REQUIRED: для Gateway добавьте --read-tree.')
        if source.traversal == 'recursive':
            from sarex_loader.recursive_gateway import collect_recursive_tree

            collect_recursive_tree(source, index, checkpoint=checkpoint, progress=progress)
        else:
            from sarex_loader.gateway_tree import collect_gateway_tree

            collect_gateway_tree(source, paths, index)
    elif source.source == 'browser':
        if not allow_browser:
            raise ValidationError('TREE_READ_REQUIRED: для чтения браузера добавьте --read-tree.')
        from sarex_loader.browser_tree import collect_browser_tree

        collect_browser_tree(source, paths, index)
    else:
        total = 0
        observation = None
        parts = {}
        for path, digest in source.exports:
            raw = read_snapshot(path, source.max_response_bytes)
            total += len(raw)
            if total > 128 * 1024**2 or hashlib.sha256(raw).hexdigest() != digest:
                raise ValidationError('TREE_SOURCE_CHANGED_OR_LIMIT')
            add_response(index, raw, source.max_response_bytes)
            envelope = decode_payload(raw, max_nodes=MAX_GATEWAY_NODES)
            if '_sarex_loader' in envelope:
                if observation is not None:
                    raise ValidationError('TREE_OBSERVATION_INVALID')
                observation = envelope['_sarex_loader']
            if '_sarex_part' in envelope:
                number = envelope['_sarex_part']
                if type(number) is not int or not 0 <= number < 256 or number in parts:
                    raise ValidationError('TREE_SNAPSHOT_PARTS_INVALID')
                parts[number] = hashlib.sha256(_snapshot_bytes(
                    {'documents': envelope['documents']})).hexdigest()
        if parts or isinstance(observation, dict) and 'parts_sha256' in observation:
            expected = observation.get('parts_sha256') if isinstance(observation, dict) else None
            if (type(expected) is not list or len(expected) != len(source.exports)
                    or set(parts) != set(range(len(expected)))
                    or [parts[i] for i in range(len(expected))] != expected):
                raise ValidationError('TREE_SNAPSHOT_PARTS_INVALID')
        if observation is not None:
            restore_observation(source, index, observation)
        if source.queried_folder_ids is not None:
            if any(i not in index.documents or not index.documents[i].is_folder
                   for i in source.queried_folder_ids):
                raise ValidationError('TREE_REQUEST_SCOPE_UNVERIFIED: нет объявленной папки.')
            index.queried_folders.update(source.queried_folder_ids)
    return index


def validate_tree_mode(source, allow_browser):
    if type(allow_browser) is not bool:
        raise ValidationError('TREE_READ_MODE_INVALID')
    if allow_browser and (source is None or source.source not in {'browser', 'gateway'}):
        raise ValidationError('TREE_BROWSER_CONFIG_REQUIRED: нужен source=browser или gateway.')
    if source is not None and source.source in {'browser', 'gateway'} and not allow_browser:
        raise ValidationError('TREE_READ_REQUIRED: для свежего дерева добавьте --read-tree.')


def resolve_observed_path(index, root, parts):
    """Keep FolderResolver authoritative; require every Gateway path level to be fresh."""
    result = index.resolve(root, parts)
    if (index.observation or {}).get('source') != 'gateway':
        return result
    if (index.observation or {}).get('global_error'):
        return FolderResolution(None, 'TREE_METADATA_UNAVAILABLE')
    current = root
    for part in (*parts, None):
        if current not in index.queried_folders:
            return FolderResolution(None, 'TREE_METADATA_UNAVAILABLE')
        if part is None:
            break
        child = index.child(current, part)
        if child.folder_id is None:
            return result
        current = child.folder_id
    return result


def tree_seal(source, index):
    """Stable projection: repeated live reads do not change the plan due to timestamps.

    Names/IDs/paths, disk and requested folders bind the plan. Source JSON hashes
    additionally bind local exports; no credentials or raw API metadata are retained.
    """
    value = {'disk_id': source.disk_id, 'source': source.source,
             'documents': [(d.id, d.name, d.is_folder, d.path_ids)
                           for d in sorted(index.documents.values(), key=lambda d: d.id)],
             'queried_folders': sorted(index.queried_folders),
             'exports': [digest for _, digest in source.exports]}
    if source.queried_folder_ids is not None:
        value['coverage_declared'] = True
    if source.browser_mode == 'extension':
        value.update(browser_mode=source.browser_mode, root_ids=source.root_ids)
    if source.source == 'gateway':
        value['root_ids'] = source.root_ids
        value['failed_folders'] = (index.observation or {}).get('failed_folders', {})
        if source.traversal == 'recursive':
            value['traversal'] = 'recursive'
            value['traversal_status'] = (index.observation or {}).get('traversal_status')
            value['global_error'] = (index.observation or {}).get('global_error')
    if index.observation is not None and source.source == 'json':
        value['observed_snapshot'] = True
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def tree_summary(source, index):
    from sarex_loader.tree_acceptance import acceptance_summary

    result = {'source': source.source, 'disk_id': source.disk_id,
            'max_response_bytes': source.max_response_bytes,
            'sha256': tree_seal(source, index), 'objects': len(index.documents),
            'queried_folders': len(index.queried_folders),
            'coverage_declared': source.source in {'browser', 'gateway'}
            or source.queried_folder_ids is not None or index.observation is not None,
            'folder_lookups': index.lookups, 'network_enabled': index.network_enabled,
            'server_completeness': 'UNKNOWN', 'absence_proves_no_document': False}
    if index.observation is not None:
        result.update(observation=index.observation,
                      freshness='READ_THIS_RUN' if index.network_enabled else 'SAVED_SNAPSHOT',
                      upload_authorized=False)
        if index.observation.get('source') != 'gateway':
            result['browser_mode'] = 'extension'
    else:
        result['freshness'] = 'READ_THIS_RUN' if index.network_enabled else 'UNKNOWN'
    if hasattr(index, 'refresh_metrics'):
        result['refresh_metrics'] = index.refresh_metrics
        if index.refresh_metrics.get('resumed_checkpoint'):
            result['freshness'] = 'RESUMED_MULTI_SESSION_OBSERVATION'
    result['operational_acceptance'] = acceptance_summary(index)
    return result


def observation_time(value):
    if type(value) is not str or len(value) > 40:
        raise ValidationError('TREE_OBSERVATION_INVALID')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if result.utcoffset() is None:
            raise ValueError
        return result
    except ValueError:
        raise ValidationError('TREE_OBSERVATION_INVALID') from None


def tree_snapshot(source, index):
    """Metadata only; the normal exclusive report bundle protects this local artifact."""
    if source.source not in {'browser', 'gateway'} or index.observation is None:
        return None
    value = {'documents': [
        {'id': d.id, 'name': d.name, 'path': '.'.join(map(str, d.path_ids)),
         'is_folder': d.is_folder, 'parent_id': d.path_ids[-2] if len(d.path_ids) > 1 else None}
        for d in sorted(index.documents.values(), key=lambda d: d.id)],
        '_sarex_loader': index.observation}
    return value


def _snapshot_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode()


def snapshot_payloads(value, limit):
    """Split exports without widening the existing per-response parser limits.

    The final part binds every document chunk by digest; missing, extra or altered
    chunks cannot turn an incomplete import into an apparently unique match.
    """
    documents = value['documents']
    raw = _snapshot_bytes(value)
    if len(documents) <= 5000 and len(raw) <= limit:
        return {'tree-snapshot.json': raw}
    chunks = [documents[i:i + 5000] for i in range(0, len(documents), 5000)]
    while chunks and len(chunks) <= 256:
        observation = {**value['_sarex_loader'], 'parts_sha256': [
            hashlib.sha256(_snapshot_bytes({'documents': chunk})).hexdigest() for chunk in chunks]}
        payloads = {}
        oversized = None
        for i, chunk in enumerate(chunks):
            envelope = {'documents': chunk, '_sarex_part': i}
            if i == len(chunks) - 1:
                envelope['_sarex_loader'] = observation
            raw = _snapshot_bytes(envelope)
            if len(raw) > limit:
                oversized = i
                break
            payloads[f'tree-snapshot-{i + 1:03d}.json'] = raw
        if oversized is None:
            if sum(map(len, payloads.values())) > 128 * 1024**2:
                break
            return payloads
        chunk = chunks[oversized]
        if len(chunk) < 2:
            break
        half = len(chunk) // 2
        chunks[oversized:oversized + 1] = [chunk[:half], chunk[half:]]
    raise ValidationError('TREE_SNAPSHOT_EXPORT_LIMIT')


def restore_observation(source, index, value):
    """Import our hashed metadata snapshot, never treating it as fresh or exhaustive."""
    if isinstance(value, dict) and 'parts_sha256' in value:
        value = {k: v for k, v in value.items() if k != 'parts_sha256'}
    gateway = isinstance(value, dict) and value.get('version') == 2
    recursive = isinstance(value, dict) and value.get('version') == 3
    gateway = gateway or recursive
    keys = {
            'version', 'disk_id', 'root_ids', 'queried_at', 'started_at', 'finished_at',
            'blocked_mutations', 'coverage', 'server_completeness'}
    if gateway:
        keys |= {'source', 'failed_folders'}
    if recursive:
        keys |= {'traversal_status', 'unvisited_folder_ids', 'global_error', 'context_names',
                 'root_verified', 'completeness_description'}
    if (type(value) is not dict or set(value) != keys
            or type(value['version']) is not int
            or value['version'] != (3 if recursive else 2 if gateway else 1)
            or value['disk_id'] != source.disk_id
            or value['coverage'] != ('TRAVERSED_OBSERVED_FOLDERS' if recursive else
                                    'REFRESHED_REQUIRED_PATHS' if gateway
                                     else 'TRAVERSED_OBSERVED_FOLDERS')
            or value['server_completeness'] != 'UNKNOWN' or index.observation is not None
            or type(value['blocked_mutations']) is not int or value['blocked_mutations'] < 0
            or type(value['root_ids']) is not list or not value['root_ids']
            or len(value['root_ids']) > 16
            or any(not valid_id(i) for i in value['root_ids'])
            or len(set(value['root_ids'])) != len(value['root_ids'])
            or type(value['queried_at']) is not dict or (not gateway and not value['queried_at'])
            or len(value['queried_at']) > 10000):
        raise ValidationError('TREE_OBSERVATION_INVALID')
    start, end = observation_time(value['started_at']), observation_time(value['finished_at'])
    if start > end:
        raise ValidationError('TREE_OBSERVATION_INVALID')
    failed = set()
    if gateway:
        allowed_errors = {code.value for code in ApiErrorCode} | {
            'TREE_RESPONSE_INVALID', 'TREE_PAGINATION_UNSUPPORTED',
            'INVALID_PAGINATION_METADATA',
            'TREE_REQUEST_SCOPE_UNVERIFIED', 'TREE_TOTAL_BYTES_EXCEEDED',
            'TREE_TIME_BUDGET_EXCEEDED'}
        if recursive:
            allowed_errors |= {'TREE_FOLDER_BUDGET_EXCEEDED', 'TREE_CONFLICT', 'TREE_LIMIT',
                               'TREE_ROOT_PROFILE_MISMATCH', 'TREE_INTERRUPTED',
                               'TREE_SNAPSHOT_CHANGED', 'TREE_AUTH_FAILED',
                               'TREE_SECURE_LOGIN_UNAVAILABLE', 'TREE_LOGIN_REQUIRES_TERMINAL'}
        if (value['source'] != 'gateway' or type(value['failed_folders']) is not dict
                or len(value['failed_folders']) + len(value['queried_at']) > 10000):
            raise ValidationError('TREE_OBSERVATION_INVALID')
        for key, code in value['failed_folders'].items():
            if (type(key) is not str or re.fullmatch(r'[1-9][0-9]{0,18}', key) is None
                    or not valid_id(int(key)) or type(code) is not str or code not in allowed_errors
                    or key in value['queried_at']):
                raise ValidationError('TREE_OBSERVATION_INVALID')
            failed.add(int(key))
    scopes = set()
    for key, stamp in value['queried_at'].items():
        if not key.isascii() or not key.isdecimal() or str(int(key)) != key:
            raise ValidationError('TREE_OBSERVATION_INVALID')
        identifier = int(key)
        if (not valid_id(identifier) or identifier not in index.documents
                or not index.documents[identifier].is_folder
                or not any(root in index.documents[identifier].path_ids
                           for root in value['root_ids'])
                or not start <= observation_time(stamp) <= end):
            raise ValidationError('TREE_OBSERVATION_INVALID')
        scopes.add(identifier)
    if not set(value['root_ids']) <= scopes | failed or (
            source.queried_folder_ids is not None and set(source.queried_folder_ids) != scopes):
        raise ValidationError('TREE_OBSERVATION_INVALID')
    index.queried_folders.update(scopes)
    if recursive:
        from sarex_loader.recursive_gateway import validate_observation

        validate_observation(value, index)
        index.context_names = {int(k): v for k, v in value['context_names'].items()}
    index.observation = value
