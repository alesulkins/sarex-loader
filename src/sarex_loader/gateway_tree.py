"""Fresh selective metadata reads using the existing Documentations authentication."""

import getpass
import hashlib
import json
import re
import ssl
import sys
import time
import warnings
from contextlib import contextmanager
from datetime import UTC, datetime
from types import MappingProxyType

from sarex_loader.api_client import (
    ApiSettings,
    _read_response_body,
    _remaining,
    _status_error,
    _tls_context,
)
from sarex_loader.api_models import ApiError, ApiErrorCode
from sarex_loader.api_transport import BearerToken, GetRequest
from sarex_loader.auth import AuthSession
from sarex_loader.browser_tree import collect_paths
from sarex_loader.folder_resolver import FolderResolver
from sarex_loader.gateway_diagnostic_policy import GatewayLoginPolicy
from sarex_loader.gateway_tree_policy import GatewayTreeReadPolicy
from sarex_loader.https_transport import ReadOnlyHTTPSTransport
from sarex_loader.safety import ValidationError


def _now():
    return datetime.now(UTC).isoformat()


@contextmanager
def gateway_login():
    """No discovery, persistence, browser credentials or automatic refresh."""
    from sarex_loader.profile_auth import active_login

    configured = active_login.get()
    if configured is not None:
        with configured() as token:
            yield token
        return
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValidationError('TREE_LOGIN_REQUIRES_TERMINAL: нужен скрытый ввод логина и пароля.')
    username = password = auth = None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            username = getpass.getpass('Логин Sarex (скрытый ввод): ')
            password = getpass.getpass('Пароль Sarex (скрытый ввод): ')
        policy = GatewayLoginPolicy()
        auth = AuthSession(
            ApiSettings('https://lk.sarex.io/api', ('https://lk.sarex.io',)),
            transport=ReadOnlyHTTPSTransport(policy, confirmed=True),
            read_only_network_enabled=True)
        auth.login(username, password)
        username = password = None
        yield lambda: auth.access_token(allow_refresh=False)
    except ApiError as exc:
        raise ValidationError(f'TREE_AUTH_FAILED: {exc.code.value}') from None
    except (getpass.GetPassWarning, EOFError):
        raise ValidationError('TREE_SECURE_LOGIN_UNAVAILABLE') from None
    finally:
        username = password = None
        if auth is not None:
            auth.logout()  # Local references only; no logout HTTP request.


def fetch_gateway(policy, access, *, response_metadata=None):
    """Single HTTPS attempt; only a successful bounded JSON body can escape."""
    if type(policy) is not GatewayTreeReadPolicy or type(access) is not BearerToken:
        raise ApiError(ApiErrorCode.ACCESS_DENIED)
    response = None
    error = body = None
    try:
        deadline = time.monotonic() + policy.timeouts.total
        request = GetRequest(
            url=policy.url, headers=MappingProxyType({
                'Accept': 'application/json', 'Accept-Encoding': 'identity',
                'Authorization': access.header_value()}),
            tls_context=_tls_context(),
            connect_timeout=min(policy.timeouts.connect, _remaining(deadline)),
            read_timeout=min(policy.timeouts.read, _remaining(deadline)), deadline=deadline)
        response = ReadOnlyHTTPSTransport(policy, confirmed=True).open(request)
        if response_metadata is not None:
            # Values may contain private URLs. Persist field names and bounded hints only.
            headers = {k.lower(): v for k, v in response.headers.items()}
            response_metadata['pagination_headers_present'] = sorted(
                k for k in headers if k in {'link', 'x-total-count', 'content-range',
                                            'x-next-page', 'x-page', 'x-per-page'})
            response_metadata['header_next_page_hint'] = bool(headers.get('x-next-page')) or (
                'rel="next"' in headers.get('link', '').casefold()
                or 'rel=next' in headers.get('link', '').casefold())
            interval = re.fullmatch(r'\S+ ([0-9]+)-([0-9]+)/([0-9]+)',
                                    headers.get('content-range', ''))
            if interval and int(interval[2]) + 1 < int(interval[3]):
                response_metadata['header_next_page_hint'] = True
            response_metadata['http_status'] = response.status
            from sarex_loader.gateway_retry import retry_after

            response_metadata['retry_after_seconds'] = retry_after(headers.get('retry-after'))
        failure = _status_error(response.status)
        if failure is not None:
            raise failure  # Do not read private error bodies.
        body = _read_response_body(response, policy.max_response_bytes, policy.timeouts, deadline)
        _remaining(deadline)
    except ApiError as exc:
        error = ApiError(exc.code, exc.status or (response.status if response else None))
    except TimeoutError:
        error = ApiError(ApiErrorCode.TIMEOUT)
    except ssl.SSLError:
        error = ApiError(ApiErrorCode.TLS_ERROR)
    except Exception:
        error = ApiError(ApiErrorCode.TRANSPORT_ERROR)
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                error = ApiError(ApiErrorCode.TRANSPORT_ERROR)
    if error is not None:
        raise error
    return body


def collect_gateway_tree(source, paths, index):
    from sarex_loader.tree_source import add_response

    if not paths:
        return  # No eligible Excel rows: no authentication or metadata requests.
    roots = sorted({root for root, _ in paths})
    if (not source.root_ids or not set(roots) <= set(source.root_ids)
            or index.documents or index.observation is not None):
        raise ValidationError('TREE_GATEWAY_SCOPE_INVALID')
    # Validate all route components and the disk before issuing even the login POST.
    collect_paths(paths, FolderResolver(), lambda _: False, max_folders=source.max_folders)
    GatewayTreeReadPolicy(source.disk_id, roots[0], source.max_response_bytes)
    observation = {
        'version': 2, 'source': 'gateway', 'disk_id': source.disk_id,
        'root_ids': roots, 'queried_at': {}, 'failed_folders': {},
        'started_at': _now(), 'finished_at': None, 'blocked_mutations': 0,
        'coverage': 'REFRESHED_REQUIRED_PATHS', 'server_completeness': 'UNKNOWN'}
    total_bytes = 0
    stop_code = None
    metrics = {'get_attempts': 0, 'requests': [], 'total_response_bytes': 0,
               'token_lifetime_seconds_assumed': 300, 'automatic_refresh': False,
               'time_budget_seconds': 240, 'required_paths': len(paths)}
    index.refresh_metrics = metrics
    started = time.monotonic()
    with gateway_login() as token:
        metrics['login_seconds'] = round(time.monotonic() - started, 3)
        collection_started = time.monotonic()
        deadline = time.monotonic() + 240  # Fits the existing 295-second access lifetime.
        index.network_enabled = True

        def fetch(folder):
            nonlocal total_bytes, stop_code
            code = stop_code
            measured = {'folder_id': folder, 'attempted': False, 'http_status': None}
            request_started = time.monotonic()
            if time.monotonic() >= deadline:
                code = stop_code = 'TREE_TIME_BUDGET_EXCEEDED'
            if code is None:
                try:
                    access = token()
                    measured['attempted'] = True
                    metrics['get_attempts'] += 1
                    raw = fetch_gateway(GatewayTreeReadPolicy(
                        source.disk_id, folder, source.max_response_bytes), access)
                    measured.update(http_status=200, response_bytes=len(raw))
                    total_bytes += len(raw)
                    if total_bytes > 128 * 1024**2:
                        stop_code = 'TREE_TOTAL_BYTES_EXCEEDED'
                        raise ValidationError(stop_code)
                    # Validate in a temporary index before publishing any part of this response.
                    pending = FolderResolver()
                    add_response(pending, raw, source.max_response_bytes, queried_folder=folder)
                    measured['pagination'] = pending.metadata[0]
                    target = pending.documents[folder]
                    if not any(root in target.path_ids for root in roots):
                        raise ValidationError('TREE_REQUEST_SCOPE_UNVERIFIED')
                    # Observed real response also includes siblings of breadcrumbs.
                    # They are navigation context, never coverage of other branches.
                    selected = [item for item in pending.documents.values()
                                if item.path_ids[:len(target.path_ids)] == target.path_ids
                                or target.path_ids[:len(item.path_ids)] == item.path_ids]
                    projected = json.dumps({'documents': [
                        {'id': item.id, 'name': item.name, 'is_folder': item.is_folder,
                         'path': '.'.join(map(str, item.path_ids))}
                        for item in selected]}, ensure_ascii=False).encode()
                    measured.update(objects=len(pending.documents), selected_objects=len(selected),
                                    direct_children=sum(len(d.path_ids) > 1
                                        and d.path_ids[-2] == folder for d in selected))
                except ApiError as exc:
                    code = exc.code.value
                    measured['http_status'] = exc.status
                    if exc.code in {ApiErrorCode.AUTHENTICATION, ApiErrorCode.REAUTH_REQUIRED,
                                    ApiErrorCode.RATE_LIMITED}:
                        stop_code = code
                except ValidationError as exc:
                    # Only fixed locally generated validation codes, no response text.
                    code = str(exc).split(':', 1)[0]
                    if code not in {'TREE_RESPONSE_INVALID', 'TREE_PAGINATION_UNSUPPORTED',
                                    'INVALID_PAGINATION_METADATA',
                                    'TREE_REQUEST_SCOPE_UNVERIFIED', 'TREE_TOTAL_BYTES_EXCEEDED'}:
                        raise
                else:
                    # Conflicts across responses are fatal, never publish a mixed tree.
                    add_response(index, projected, source.max_response_bytes, queried_folder=folder)
                    index.metadata[-1] = pending.metadata[0]
                    index.source_hashes[-1] = hashlib.sha256(raw).hexdigest()
                    observation['queried_at'][str(folder)] = _now()
            measured.update(elapsed_seconds=round(time.monotonic() - request_started, 3),
                            error=code)
            metrics['requests'].append(measured)
            metrics['total_response_bytes'] = total_bytes
            if code is not None:
                observation['failed_folders'][str(folder)] = code
                from sarex_loader.messages import describe

                print(f'Папка {folder}: обновление пропущено. {describe(code)}', file=sys.stderr)
                return False
            return True

        collect_paths(paths, index, fetch, max_folders=source.max_folders)
        metrics['collection_seconds'] = round(time.monotonic() - collection_started, 3)
    metrics['total_seconds'] = round(time.monotonic() - started, 3)
    observation['finished_at'] = _now()
    index.observation = observation
