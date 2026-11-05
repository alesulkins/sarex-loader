"""Safe structural diagnostics: fixed field names/types/reasons only, never response values."""

from sarex_loader.api_models import MAX_ANCESTORS, valid_id
from sarex_loader.api_transport import BearerToken
from sarex_loader.api_upload_models import bundle_issue
from sarex_loader.safety import ValidationError
from sarex_loader.types_validation import types_issue, types_shape

DOCUMENT_FIELDS = ('id', 'name', 'is_folder', 'disk_id', 'path', 'workspace_id', 'files', 'folders')
WRAPPERS = ('data', 'results', 'ancestors', 'documents', 'types')


def json_type(value):
    return {type(None): 'null', bool: 'boolean', int: 'number', float: 'number',
            str: 'string', list: 'array', dict: 'object'}.get(type(value), 'unknown')


def shape(value, kind):
    fields = (('access', 'refresh') if kind == 'token' else ('access',) if kind == 'refresh'
              else DOCUMENT_FIELDS if kind in {'document', 'ancestors'}
              else ('id', 'document_id', 'upload_status') if kind == 'bundle'
              else ('types',) if kind == 'types' else ())
    result = {'json_type': json_type(value)}
    if type(value) is dict:
        result['expected_keys_present'] = {key: key in value for key in fields}
        result['expected_field_types'] = {key: json_type(value[key])
                                          for key in fields if key in value}
        result['known_envelope_keys_present'] = {key: key in value for key in WRAPPERS}
    elif type(value) is list:
        result['array_length'] = len(value)
    if kind == 'types':
        result.update(types_shape(value))
    return result


def document_issue(value):
    if type(value) is not dict:
        return {'reason': 'EXPECTED_DOCUMENT_OBJECT'}
    for key in ('id', 'name', 'is_folder'):
        if key not in value:
            return {'reason': 'REQUIRED_FIELD_MISSING', 'field': key}
    if not valid_id(value['id']):
        return {'reason': 'EXPECTED_POSITIVE_INT64', 'field': 'id'}
    if type(value['name']) is not str:
        return {'reason': 'EXPECTED_STRING', 'field': 'name'}
    if not value['name'].strip():
        return {'reason': 'EMPTY_REQUIRED_STRING', 'field': 'name'}
    if type(value['is_folder']) is not bool:
        return {'reason': 'EXPECTED_BOOLEAN', 'field': 'is_folder'}
    for key in ('disk_id', 'path', 'workspace_id'):
        if key in value and type(value[key]) is not str:
            return {'reason': 'EXPECTED_STRING', 'field': key}
    for key in ('files', 'folders'):
        if key not in value:
            continue
        items = value[key]
        if type(items) is not list:
            return {'reason': 'EXPECTED_ID_ARRAY', 'field': key}
        for index, item in enumerate(items):
            if not valid_id(item):
                return {'reason': 'EXPECTED_POSITIVE_INT64', 'field': key,
                        'item_index': index, 'item_type': json_type(item)}
        if len(items) != len(set(items)):
            return {'reason': 'DUPLICATE_CHILD_ID', 'field': key}
        if value['id'] in items:
            return {'reason': 'SELF_CHILD_ID', 'field': key}
    if set(value.get('files', [])) & set(value.get('folders', [])):
        return {'reason': 'CHILD_KIND_CONFLICT'}
    return None


def validation_issue(value, kind):
    if kind == 'bundle':
        return bundle_issue(value)
    if kind == 'types':
        return types_issue(value)
    if kind in {'token', 'refresh'}:
        if type(value) is not dict:
            return {'reason': 'EXPECTED_TOKEN_OBJECT'}
        for key in (('access', 'refresh') if kind == 'token' else ('access',)):
            if key not in value:
                return {'reason': 'REQUIRED_FIELD_MISSING', 'field': key}
            try:
                BearerToken(value[key])
            except ValidationError:
                return {'reason': 'INVALID_BEARER_FORMAT', 'field': key,
                        'field_type': json_type(value[key])}
        return None
    if kind == 'document':
        return document_issue(value)
    if kind != 'ancestors':
        return None
    if type(value) is not list:
        return {'reason': 'EXPECTED_ANCESTORS_ARRAY'}
    if len(value) > MAX_ANCESTORS:
        return {'reason': 'ANCESTORS_COUNT_LIMIT'}
    seen = set()
    for index, item in enumerate(value):
        issue = document_issue(item)
        if issue:
            return {**issue, 'ancestor_index': index, 'item_shape': shape(item, 'document')}
        if item['id'] in seen:
            return {'reason': 'DUPLICATE_ANCESTOR_ID', 'ancestor_index': index}
        seen.add(item['id'])
    return None
