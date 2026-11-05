"""Local, literal name checks. No I/O, URL construction, normalization or logging."""

import hashlib
import hmac
import re
import unicodedata
from typing import Literal, TypedDict

from sarex_loader.api_models import MAX_STRING, Document, valid_id
from sarex_loader.safety import ValidationError


class NameCheckResult(TypedDict):
    status: Literal['MATCH', 'NO_MATCH']
    id: int


def validate_name(value: str) -> str:
    # Same text bounds as API JSON validation; this text is never treated as a path.
    if (type(value) is not str or not value.strip() or len(value) > MAX_STRING
            or any(unicodedata.category(c).startswith('C') for c in value)):
        raise ValidationError('Некорректное имя: нужен непустой текст без управляющих символов.')
    return value  # Do not strip, casefold, append an extension, or normalize Unicode.


def validate_name_digest(value: str) -> str:
    if type(value) is not str or not re.fullmatch(r'[0-9a-f]{64}', value):
        raise ValidationError('Нужен SHA-256 из 64 строчных шестнадцатеричных символов.')
    return value


def _result(identifier: int, equal: bool) -> NameCheckResult:
    if not valid_id(identifier):
        raise ValidationError('Нужен положительный int64 ID документа.')
    return {'status': 'MATCH' if equal else 'NO_MATCH', 'id': identifier}


def check_document_name(document: Document, expected_name: str) -> NameCheckResult:
    expected = validate_name(expected_name).encode('utf-8')
    actual = validate_name(document.name).encode('utf-8')
    return _result(document.id, hmac.compare_digest(actual, expected))


def check_name_digest(identifier: int, name_sha256: str, expected_name: str) -> NameCheckResult:
    digest = validate_name_digest(name_sha256)
    expected = hashlib.sha256(validate_name(expected_name).encode('utf-8')).hexdigest()
    return _result(identifier, hmac.compare_digest(digest, expected))
