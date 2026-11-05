"""Postman request fields and defensive response projections, not inferred server schemas."""

import re
from dataclasses import dataclass
from datetime import datetime

from sarex_loader.api_models import ApiError, ApiErrorCode, JSONValue, valid_id
from sarex_loader.folder_resolver import safe_component
from sarex_loader.safety import ValidationError
from sarex_loader.types_validation import types_issue, types_items


def path_id(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value):
        raise ValidationError('Нужен безопасный строковый идентификатор API.')
    return value


@dataclass(frozen=True, repr=False)
class BundleDraft:
    disk_id: str
    document_type: str
    key: str
    filename: str
    date: str

    def __post_init__(self) -> None:
        for value in (self.disk_id, self.document_type, self.key):
            path_id(value)
        if not safe_component(self.filename) or not self.filename.lower().endswith('.pdf'):
            raise ValidationError('Нужно безопасное имя PDF без преобразований.')
        if not isinstance(self.date, str) or len(self.date) > 64:
            raise ValidationError('Нужна явная ISO-дата Bundle.')
        try:
            parsed = datetime.fromisoformat(self.date)
        except (ValueError, TypeError):
            raise ValidationError('Дата Bundle должна быть ISO-датой с часовым поясом.') from None
        if parsed.tzinfo is None:
            raise ValidationError('Часовой пояс даты Bundle должен быть задан явно.')

    def payload(self) -> dict[str, object]:
        return {'disk_id': self.disk_id, 'type': self.document_type,
                'keys': [{'key': self.key, 'type': 'file', 'name': self.filename}],
                'date': self.date}


@dataclass(frozen=True, repr=False)
class Bundle:
    id: str
    document_id: int | None
    upload_status: str | None


def bundle_issue(value: JSONValue) -> dict[str, str] | None:
    """Safe reasons shared by the parser and diagnostics, never response values."""
    if not isinstance(value, dict):
        return {'reason': 'EXPECTED_BUNDLE_OBJECT'}
    try:
        path_id(value.get('id'))
    except ValidationError:
        return {'reason': 'EXPECTED_SAFE_BUNDLE_ID', 'field': 'id'}
    document_id = value.get('document_id')
    status = value.get('upload_status')
    # A newly created, unattached Bundle may explicitly return JSON null.
    # This does NOT mean that an attachment operation has been confirmed.
    if document_id is not None and not valid_id(document_id):
        return {'reason': 'EXPECTED_NULL_OR_POSITIVE_INT64', 'field': 'document_id'}
    if 'upload_status' in value:
        if type(status) is not str:
            return {'reason': 'EXPECTED_STRING', 'field': 'upload_status'}
        # Exact Swagger BundleUploadStatus enum, not guesses from the live string type.
        if status not in ('created', 'uploaded'):
            return {'reason': 'UNDOCUMENTED_UPLOAD_STATUS', 'field': 'upload_status'}
    return None


def parse_bundle(value: JSONValue) -> Bundle:
    if bundle_issue(value) is not None:
        raise ApiError(ApiErrorCode.INVALID_RESPONSE)
    return Bundle(value['id'], value.get('document_id'), value.get('upload_status'))


@dataclass(frozen=True, repr=False)
class TypeField:
    key: str
    file: bool | None
    can_upload: bool | None


@dataclass(frozen=True, repr=False)
class DocumentType:
    name: str
    fields: tuple[TypeField, ...]


def parse_types(value: JSONValue) -> tuple[DocumentType, ...]:
    if types_issue(value) is not None:
        raise ApiError(ApiErrorCode.INVALID_RESPONSE)
    return tuple(DocumentType(item['name'], tuple(
        TypeField(field['key'], field.get('file'), field.get('can_be_uploaded_by_user'))
        for field in item['fields'])) for item in types_items(value))
