"""Visit every observed folder of ONE selected root. No inference from Excel paths."""

import hashlib
import json
import time
from collections import deque
from datetime import UTC, datetime

from sarex_loader import gateway_tree
from sarex_loader.api_client import Timeouts
from sarex_loader.api_models import ApiError, ApiErrorCode, valid_id
from sarex_loader.folder_resolver import FolderResolver, tree_component
from sarex_loader.gateway_retry import GetRetrier
from sarex_loader.gateway_tree_policy import GatewayTreeReadPolicy
from sarex_loader.safety import ValidationError

PROFILE_ROOTS = {
    'sk': (2066367, '06-Отчеты по строительному контролю'),
    'vk': (2067117, '08-Входной контроль МТР'),
}
MAX_TOTAL_BYTES = 512 * 1024**2


def _now():
    return datetime.now(UTC).isoformat()


def collect_recursive_tree(source, index, *, progress=None, checkpoint=None, retrier=None):
    from sarex_loader.tree_source import add_response

    if (source.source != 'gateway' or len(source.root_ids) != 1 or index.documents
            or index.observation is not None):
        raise ValidationError('TREE_GATEWAY_SCOPE_INVALID')
    root, = source.root_ids
    GatewayTreeReadPolicy(source.disk_id, root, source.max_response_bytes)
    names = {i: name for i, name in PROFILE_ROOTS.values()}
    queue, scheduled = deque([root]), {root}
    observed = {
        'version': 3, 'source': 'gateway', 'disk_id': source.disk_id, 'root_ids': [root],
        'queried_at': {}, 'failed_folders': {}, 'started_at': _now(), 'finished_at': None,
        'blocked_mutations': 0, 'coverage': 'TRAVERSED_OBSERVED_FOLDERS',
        'server_completeness': 'UNKNOWN', 'traversal_status': 'IN_PROGRESS',
        'unvisited_folder_ids': [], 'global_error': None, 'context_names': {},
        'root_verified': False, 'completeness_description': 'Полнота не подтверждена',
    }
    index.observation = observed
    index.context_names = {}
    metrics = {'get_attempts': 0, 'requests': [], 'total_response_bytes': 0,
               'token_lifetime_seconds_assumed': 300, 'time_budget_seconds': None,
               'cache_hits': 0, 'unique_folders_discovered': 1}
    index.refresh_metrics = metrics
    started = time.monotonic()
    root_path = None
    retrier = retrier or GetRetrier()
    if checkpoint and checkpoint.records:
        root_path = _restore_checkpoint(source, index, checkpoint, observed)
        scheduled.update(d.id for d in index.documents.values() if d.is_folder)
        queue = deque(sorted(scheduled - index.queried_folders))
    metrics['cached_folders'] = len(index.queried_folders)
    metrics['resumed_checkpoint'] = bool(metrics['cached_folders'])
    visited_this_session = 0
    token = None
    try:
        with gateway_tree.gateway_login() as token:
            index.network_enabled = True
            metrics['login_seconds'] = round(time.monotonic() - started, 3)
            while queue:
                if visited_this_session >= source.max_folders:
                    observed['global_error'] = 'TREE_FOLDER_BUDGET_EXCEEDED'
                    break
                folder = queue.popleft()
                visited_this_session += 1
                measured = {'folder_id': folder, 'attempted': False, 'http_status': None,
                            'error': None}
                request_started = time.monotonic()
                try:
                    measured['attempted'] = True
                    raw = retrier.fetch(GatewayTreeReadPolicy(
                        source.disk_id, folder, source.max_response_bytes,
                        timeouts=Timeouts(connect=15, read=20, total=45)), token, measured)
                    measured.update(http_status=200, response_bytes=len(raw))
                    metrics['total_response_bytes'] += len(raw)
                    if metrics['total_response_bytes'] > MAX_TOTAL_BYTES:
                        raise ValidationError('TREE_TOTAL_BYTES_EXCEEDED')
                    if measured.get('header_next_page_hint'):
                        raise ValidationError('TREE_PAGINATION_UNSUPPORTED')
                    pending = FolderResolver()
                    add_response(pending, raw, source.max_response_bytes, queried_folder=folder)
                    measured['pagination'] = pending.metadata[0]
                    target = pending.documents[folder]
                    if folder == root:
                        if root in names and target.name != names[root]:
                            raise ValidationError('TREE_ROOT_PROFILE_MISMATCH')
                        root_path = target.path_ids
                        observed['root_verified'] = True
                        index.context_names = {
                            i: pending.documents[i].name for i in root_path[:-1]
                            if i in pending.documents}
                        observed['context_names'] = {
                            str(i): n for i, n in index.context_names.items()}
                    if (not root_path or target.path_ids[:len(root_path)] != root_path
                            or folder != root and index.documents.get(folder) != target):
                        raise ValidationError('TREE_REQUEST_SCOPE_UNVERIFIED')
                    # Breadcrumb siblings are navigation context, never another branch to GET.
                    selected = [d for d in pending.documents.values()
                                if d.path_ids[:len(root_path)] == root_path
                                and (d.path_ids[:len(target.path_ids)] == target.path_ids
                                     or target.path_ids[:len(d.path_ids)] == d.path_ids)]
                    projected = json.dumps({'documents': [
                        {'id': d.id, 'name': d.name, 'is_folder': d.is_folder,
                         'path': '.'.join(map(str, d.path_ids))} for d in selected]},
                        ensure_ascii=False).encode()
                    add_response(index, projected, source.max_response_bytes, queried_folder=folder)
                    index.metadata[-1] = pending.metadata[0]
                    index.source_hashes[-1] = hashlib.sha256(raw).hexdigest()
                    observed['queried_at'][str(folder)] = _now()
                    if checkpoint:
                        checkpoint.save_folder({
                            'folder_id': folder, 'payload': json.loads(projected),
                            'metadata': pending.metadata[0], 'source_hash': index.source_hashes[-1],
                            'queried_at': observed['queried_at'][str(folder)],
                            'context_names': observed['context_names'],
                            'calls': measured['attempts']})
                    direct = [d for d in selected if len(d.path_ids) > 1
                              and d.path_ids[-2] == folder]
                    measured.update(direct_children=len(direct),
                                    direct_folders=sum(d.is_folder for d in direct),
                                    direct_files=sum(not d.is_folder for d in direct),
                                    objects_in_response=len(pending.documents))
                    for d in selected:
                        if d.is_folder and d.id not in scheduled:
                            scheduled.add(d.id)
                            queue.append(d.id)
                        elif d.is_folder:
                            metrics['cache_hits'] += 1
                except (ApiError, ValidationError) as exc:
                    code = (exc.code.value if isinstance(exc, ApiError)
                            else str(exc).split(':', 1)[0])
                    measured['error'] = code
                    if isinstance(exc, ApiError):
                        measured['http_status'] = exc.status
                    observed['failed_folders'][str(folder)] = code
                    if (folder == root or code in {
                            'TREE_CONFLICT', 'TREE_SNAPSHOT_CHANGED', 'TREE_LIMIT',
                            'TREE_TOTAL_BYTES_EXCEEDED', ApiErrorCode.AUTHENTICATION.value,
                            ApiErrorCode.REAUTH_REQUIRED.value}):
                        observed['global_error'] = code
                finally:
                    measured['elapsed_seconds'] = round(time.monotonic() - request_started, 3)
                    metrics['requests'].append(measured)
                    if checkpoint and folder not in index.queried_folders:
                        checkpoint.save_calls(measured.get('attempts', []))
                if progress:
                    progress(len(index.queried_folders), len(queue), len(index.documents))
                if observed['global_error']:
                    break
    except (ApiError, ValidationError) as exc:
        code = exc.code.value if isinstance(exc, ApiError) else str(exc).split(':', 1)[0]
        observed['global_error'] = code
        if not observed['root_verified']:
            observed['failed_folders'][str(root)] = code
    except KeyboardInterrupt:
        observed['global_error'] = 'TREE_INTERRUPTED'
    observed['unvisited_folder_ids'] = sorted(scheduled - index.queried_folders)
    incomplete = bool(observed['failed_folders'] or observed['unvisited_folder_ids']
                      or observed['global_error'])
    observed['traversal_status'] = 'INCOMPLETE' if incomplete else 'COMPLETED_OBSERVED_TREE'
    observed['completeness_description'] = (
        'Неполнота обнаружена: обход доступных папок не завершён'
        if incomplete else 'Обход наблюдаемого дерева завершён; '
        'полнота серверной выдачи не подтверждена')
    observed['finished_at'] = _now()
    metrics['get_attempts'] = len(retrier.calls)
    metrics['get_retries'] = sum(c['attempt'] > 1 for c in retrier.calls)
    metrics['attempt_log'] = retrier.calls
    metrics['recorded_gets_previous_sessions'] = len(checkpoint.previous_calls) if checkpoint else 0
    metrics['recorded_gets_total'] = (metrics['get_attempts']
                                     + metrics['recorded_gets_previous_sessions'])
    metrics['pdf_documents'] = sum(not d.is_folder and d.name.lower().endswith('.pdf')
                                   for d in index.documents.values())
    metrics.update(total_seconds=round(time.monotonic() - started, 3),
                   unique_folders_discovered=len(scheduled),
                   folders_read=len(index.queried_folders),
                   folders_unchecked=len(observed['unvisited_folder_ids']),
                   documents=sum(not d.is_folder for d in index.documents.values()),
                   folders=sum(d.is_folder for d in index.documents.values()))
    if token is not None and hasattr(token, 'metrics'):
        metrics.update(token.metrics)
    if checkpoint:
        checkpoint.finish(not incomplete)
    return index


def _restore_checkpoint(source, index, checkpoint, observed):
    from sarex_loader.tree_source import add_response, observation_time

    root, = source.root_ids
    def depth(record):
        target = next(d for d in record['payload']['documents'] if d['id'] == record['folder_id'])
        return len(target['path'].split('.'))
    try:
        for record in sorted(checkpoint.records, key=depth):
            folder = record['folder_id']
            if folder in index.queried_folders:
                raise ValueError
            add_response(index, json.dumps(record['payload']).encode(),
                         source.max_response_bytes, queried_folder=folder)
            d = index.documents[folder]
            if root not in d.path_ids or not d.is_folder:
                raise ValueError
            observation_time(record['queried_at'])
            observed['queried_at'][str(folder)] = record['queried_at']
            index.metadata[-1] = record['metadata']
            index.source_hashes[-1] = record['source_hash']
            if folder == root:
                expected = {i: n for i, n in PROFILE_ROOTS.values()}.get(root)
                if expected and d.name != expected:
                    raise ValueError
                observed['root_verified'] = True
                observed['context_names'] = record['context_names']
                if any(not k.isdecimal() or not valid_id(int(k)) or not tree_component(v)
                       for k, v in record['context_names'].items()):
                    raise ValueError
                index.context_names = {int(k): v for k, v in record['context_names'].items()}
        if not observed['root_verified'] or any(root not in d.path_ids
                                                for d in index.documents.values()):
            raise ValueError
        observed['started_at'] = min(observed['queried_at'].values())
        return index.documents[root].path_ids
    except (KeyError, ValueError, TypeError, StopIteration):
        raise ValidationError('Checkpoint повреждён или выходит за выбранный корень.') from None


def validate_observation(value, index):
    """Import remains an historical observation, never a fresh or complete server proof."""
    if (value['traversal_status'] not in {'INCOMPLETE', 'COMPLETED_OBSERVED_TREE'}
            or type(value['root_verified']) is not bool
            or type(value['unvisited_folder_ids']) is not list
            or any(not valid_id(i) for i in value['unvisited_folder_ids'])
            or type(value['context_names']) is not dict
            or any(type(k) is not str or not k.isascii() or not k.isdecimal()
                   or not valid_id(int(k))
                   or not tree_component(n) for k, n in value['context_names'].items())
            or value['global_error'] is not None and not isinstance(value['global_error'], str)
            or not isinstance(value['completeness_description'], str)):
        raise ValidationError('TREE_OBSERVATION_INVALID')
    if value['traversal_status'] == 'COMPLETED_OBSERVED_TREE' and (
            value['failed_folders'] or value['global_error'] or value['unvisited_folder_ids']
            or not value['root_verified']
            or any(d.is_folder and d.id not in index.queried_folders
                   for d in index.documents.values())):
        raise ValidationError('TREE_OBSERVATION_INVALID')
