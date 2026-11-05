"""Shared types-response validation; diagnostics contain fixed labels and types only."""

import re
from itertools import islice


def kind(value):
    return {type(None): 'null', bool: 'boolean', int: 'number', float: 'number',
            str: 'string', list: 'array', dict: 'object'}.get(type(value), 'unknown')


def structure(value, fields):
    result = {'json_type': kind(value)}
    if type(value) is dict:
        result['expected_keys_present'] = {key: key in value for key in fields}
        result['expected_field_types'] = {key: kind(value[key]) for key in fields if key in value}
    return result


def types_items(value):
    """Use only AFTER types_issue succeeds; no recursive search or wrapper guessing."""
    return value['types'] if type(value) is dict else value


def types_shape(value):
    """Bounded structural sample of the known types field; never emit names or keys' values."""
    result = {}
    if type(value) is dict:
        result['types_present'] = 'types' in value
        result['types_value_type'] = kind(value['types']) if 'types' in value else 'missing'
        result['other_envelope_key_count'] = len(value) - int('types' in value)
        items = value.get('types')
    else:
        items = value
    if type(items) is dict:
        # A map is NOT accepted as a types array. Describe only its values' structure;
        # dictionary keys can themselves contain document names or other private data.
        result.update(types_object_value_count=len(items), object_sample_limit=3,
                      object_sample_truncated=len(items) > 3,
                      object_value_samples=_item_samples(items.values()))
        return result
    if type(items) is not list:
        return result
    result.update(types_count=len(items), item_sample_limit=3,
                  item_sample_truncated=len(items) > 3)
    result['item_samples'] = _item_samples(items)
    return result


def _item_samples(items):
    samples = []
    for index, item in enumerate(islice(items, 3)):
        sample = {'type_index': index, **structure(item, ('name', 'fields'))}
        if type(item) is dict and type(item.get('fields')) is list:
            fields = item['fields']
            sample.update(field_count=len(fields), field_sample_limit=3,
                          field_sample_truncated=len(fields) > 3)
            sample['field_samples'] = [
                {'field_index': i, **structure(f, ('key', 'file', 'can_be_uploaded_by_user'))}
                for i, f in enumerate(fields[:3])]
        samples.append(sample)
    return samples


def types_issue(value):
    """The exact same checks serve parse_types and its read-only diagnostic."""
    if type(value) is dict:
        if 'types' not in value:
            return {'reason': 'REQUIRED_TYPES_FIELD_MISSING', 'field': 'types'}
        if value.keys() != {'types'}:
            return {'reason': 'UNEXPECTED_TYPES_ENVELOPE_KEYS'}
        if type(value['types']) is not list:
            return {'reason': 'EXPECTED_TYPES_FIELD_ARRAY', 'field': 'types'}
        value = types_items(value)
    if type(value) is not list:
        return {'reason': 'EXPECTED_TYPES_ARRAY'}
    seen_types = set()
    for index, item in enumerate(value):
        location = {'type_index': index, 'item_shape': structure(item, ('name', 'fields'))}
        if type(item) is not dict:
            return {**location, 'reason': 'EXPECTED_TYPE_OBJECT'}
        for key in ('name', 'fields'):
            if key not in item:
                return {**location, 'reason': 'REQUIRED_FIELD_MISSING', 'field': key}
        if type(item['name']) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', item['name']):
            return {**location, 'reason': 'INVALID_TYPE_IDENTIFIER', 'field': 'name'}
        if item['name'] in seen_types:
            return {**location, 'reason': 'DUPLICATE_TYPE_IDENTIFIER', 'field': 'name'}
        seen_types.add(item['name'])
        if type(item['fields']) is not list:
            return {**location, 'reason': 'EXPECTED_FIELDS_ARRAY', 'field': 'fields'}
        seen_keys = set()
        for field_index, field in enumerate(item['fields']):
            where = {**location, 'field_index': field_index,
                     'field_shape': structure(field, ('key', 'file', 'can_be_uploaded_by_user'))}
            if type(field) is not dict:
                return {**where, 'reason': 'EXPECTED_TYPE_FIELD_OBJECT'}
            if 'key' not in field:
                return {**where, 'reason': 'REQUIRED_FIELD_MISSING', 'field': 'key'}
            if type(field['key']) is not str or not re.fullmatch(
                    r'[A-Za-z0-9_-]{1,128}', field['key']):
                return {**where, 'reason': 'INVALID_KEY_IDENTIFIER', 'field': 'key'}
            if field['key'] in seen_keys:
                return {**where, 'reason': 'DUPLICATE_KEY_IDENTIFIER', 'field': 'key'}
            seen_keys.add(field['key'])
            for flag in ('file', 'can_be_uploaded_by_user'):
                if flag in field and type(field[flag]) is not bool:
                    return {**where, 'reason': 'EXPECTED_BOOLEAN', 'field': flag}
    return None
