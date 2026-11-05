"""Minimal identifiers for reconciliation, never proof of API success or ownership."""

import re

from sarex_loader.api_models import valid_id
from sarex_loader.safety import ValidationError

CANDIDATE_PHASES = frozenset({'CREATE_BUNDLE', 'UPLOAD_FINISH', 'CREATE_DOCUMENT'})


def safe_bundle_id(value):
    return type(value) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value) is not None


def response_candidates(phase, value):
    """Only call on a bounded, fully decoded HTTP 200 JSON body. No nested guessing."""
    if phase not in CANDIDATE_PHASES:
        raise ValidationError('Фаза не поддерживает идентификаторы ответа.')
    if type(value) is not dict:
        return None, None
    if phase == 'CREATE_DOCUMENT':
        return None, value['id'] if valid_id(value.get('id')) else None
    bundle = value['id'] if safe_bundle_id(value.get('id')) else None
    document = value['document_id'] if valid_id(value.get('document_id')) else None
    return bundle, document
