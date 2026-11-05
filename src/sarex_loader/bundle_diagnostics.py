"""CREATE_BUNDLE structure and a narrowly bounded status observation, never raw bodies."""

import re
import time

from sarex_loader.api_models import ApiError, decode_payload
from sarex_loader.api_transport import BearerToken
from sarex_loader.api_upload_models import bundle_issue, parse_bundle
from sarex_loader.gateway_diagnostic_metadata import safe_response_metadata
from sarex_loader.read_only_policy import DOCUMENTATION_BASE
from sarex_loader.response_shape import json_type
from sarex_loader.safety import ValidationError

BUNDLE_ROUTE = '/v1/bundles'
BUNDLE_REQUEST_PATH = '/documentations/api/v1/bundles'
CUSTOMER_BUNDLE_URL = 'https://api.sarex.io/documentations/api/v1/bundles'
MAX_DIAGNOSTIC_BODY = 64 * 1024


def document_bundle_observation(value, expected_bundle, document_id):
    """Structural evidence for an explicit GET, not permission to reconcile a journal."""
    result = {'bundle_link_confirmed': False, 'bundles_present': 'bundles' in value}
    if 'bundles' not in value:
        return {**result, 'bundle_reason': 'BUNDLES_ABSENT'}
    items = value['bundles']
    result['bundles_type'] = json_type(items)
    if items is None:
        # Observed on GET 7978396: a valid, unexpanded projection, not zero links.
        return {**result, 'bundles_count': None, 'bundle_item_shapes': [],
                'bundle_reason': 'BUNDLES_NOT_EXPANDED', 'bundle_link_assessment': 'UNKNOWN'}
    if type(items) is not list:
        return {**result, 'bundle_reason': 'EXPECTED_BUNDLES_ARRAY'}
    result['bundles_count'] = len(items)
    # Bounded structural sample, no arbitrary keys or response values.
    result['bundle_item_shapes'] = [
        {'item_type': json_type(item),
         'known_field_types': {key: json_type(item[key])
                              for key in ('id', 'document_id', 'upload_status') if key in item}
         if type(item) is dict else {}}
        for item in items[:3]]
    if len(items) != 1:
        return {**result, 'bundle_reason': 'EXPECTED_SINGLE_BUNDLE'}
    issue = bundle_issue(items[0])
    if issue:
        return {**result, 'bundle_reason': issue['reason']}
    linked = parse_bundle(items[0])
    result.update(bundle_id_matches=linked.id == expected_bundle,
                  linked_document_consistent=linked.document_id in (None, document_id),
                  linked_status_consistent=linked.upload_status in (None, 'uploaded'))
    confirmed = (result['bundle_id_matches'] and result['linked_document_consistent']
                 and result['linked_status_consistent'])
    return {**result, 'bundle_link_confirmed': confirmed,
            'bundle_reason': 'BUNDLE_LINK_CONFIRMED' if confirmed else 'BUNDLE_FIELDS_MISMATCH'}


def upload_status_observation(value, request):
    """Diagnostic evidence only, NOT an extension of the accepted status enum.

    Call only after a bounded HTTP 200 JSON response and durable candidate capture.
    Never trim, normalize, stringify or truncate untrusted values into printable ones.
    """
    if type(value) is not dict or 'upload_status' not in value:
        return {'upload_status_disclosure': 'ABSENT'}
    status = value['upload_status']
    if type(status) is not str or re.fullmatch(r'[a-z][a-z_-]{0,31}', status) is None:
        return {'upload_status_disclosure': 'UNSAFE_FORMAT'}
    authorization = request.headers.get('Authorization', '')
    if (not authorization.startswith('Bearer ') or not authorization[7:]
            or status in authorization[7:].lower() or authorization[7:].lower() in status
            or any(word in status for word in ('bearer', 'token', 'password', 'secret'))
            or status == value.get('id')):
        return {'upload_status_disclosure': 'REDACTED'}
    return {'upload_status_disclosure': 'SHOWN', 'observed_upload_status': status}


def request_shape(payload):
    """Called after exact body validation in the live adapter; no arbitrary JSON keys."""
    if (type(payload) is not dict or payload.keys() != {'disk_id', 'type', 'keys', 'date'}
            or type(payload['keys']) is not list or len(payload['keys']) != 1
            or type(payload['keys'][0]) is not dict
            or payload['keys'][0].keys() != {'key', 'type', 'name'}):
        raise ValidationError('Некорректная структура Bundle для диагностики.')
    return {'request_method': 'POST', 'request_path': BUNDLE_REQUEST_PATH,
            'request_content_type': 'application/json',
            'payload_keys': sorted(payload), 'key_item_keys': sorted(payload['keys'][0]),
            'key_item_count': 1}


def contract_preview(config):
    url = DOCUMENTATION_BASE + BUNDLE_ROUTE
    if url != CUSTOMER_BUNDLE_URL:
        raise ValidationError('CREATE_BUNDLE_URL_CONTRACT_MISMATCH')
    return {**request_shape(config.draft().payload()), 'request_url': url,
            'customer_url_matches': True, 'request_sent': False,
            'response_category': 'NOT_REQUESTED'}


def response_content_type(response, request):
    # The shared helper accepts only known media types; parameters/request IDs are not emitted.
    token = BearerToken(request.headers['Authorization'][7:])
    return safe_response_metadata(response.headers, token)['content_type']


def error_response_shape(response, content_type, *, deadline, read_timeout):
    """Best-effort classification of an already received error, never a new HTTP request.

    A diagnostic read failure must NOT replace the original HTTP error/outcome.
    Non-JSON bodies are classified by declared MIME only, not read or interpreted.
    """
    if content_type not in {'application/json', 'application/problem+json'}:
        category = {'text/html': 'HTML_DECLARED', 'text/plain': 'TEXT_DECLARED',
                    'application/octet-stream': 'BINARY_DECLARED'}.get(
                        content_type, 'UNSUPPORTED_OR_MISSING_CONTENT_TYPE')
        return {'response_category': category}
    body = bytearray()
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {'response_category': 'BODY_READ_TIMEOUT'}
            size = min(65536, MAX_DIAGNOSTIC_BODY - len(body) + 1)
            chunk = response.read(size, timeout=min(read_timeout, remaining))
            if type(chunk) is not bytes or len(chunk) > size:
                return {'response_category': 'BODY_READ_ERROR'}
            body.extend(chunk)
            if len(body) > MAX_DIAGNOSTIC_BODY:
                return {'response_category': 'DIAGNOSTIC_BODY_LIMIT'}
            if not chunk:
                break
        if not body:
            return {'response_category': 'EMPTY_BODY'}
        try:
            value = decode_payload(bytes(body))
        except ApiError:
            return {'response_category': 'INVALID_JSON'}
        kind = json_type(value)
        return {'response_category': 'JSON_' + kind.upper(), 'json_type': kind}
    except Exception:
        return {'response_category': 'BODY_READ_ERROR'}
    finally:
        body.clear()
