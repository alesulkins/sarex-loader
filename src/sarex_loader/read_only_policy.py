"""Closed production read-only scope; configuration cannot add hosts or write routes."""

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from sarex_loader.api_client import Timeouts
from sarex_loader.api_models import ApiError, ApiErrorCode, valid_id
from sarex_loader.config import MAX_CONFIG_BYTES, checked_path, local_path
from sarex_loader.file_safety import read_snapshot
from sarex_loader.safety import ValidationError

AUTH_BASE = 'https://lk.sarex.io/api'
DOCUMENTATION_BASE = 'https://api.sarex.io/documentations/api'


@dataclass(frozen=True, repr=False)
class ReadOnlyPolicy:
    document_ids: tuple[int, ...]
    auth_base_url: str = AUTH_BASE
    documentation_base_url: str = DOCUMENTATION_BASE
    allow_document_types: bool = False
    allow_ancestors: bool = False
    timeouts: Timeouts = field(default_factory=Timeouts)
    max_response_bytes: int = 1024**2
    max_requests: int = 4

    def __post_init__(self):
        if (self.auth_base_url != AUTH_BASE or self.documentation_base_url != DOCUMENTATION_BASE
                or not isinstance(self.document_ids, tuple) or not 1 <= len(self.document_ids) <= 16
                or any(not valid_id(identifier) for identifier in self.document_ids)
                or len(set(self.document_ids)) != len(self.document_ids)
                or type(self.allow_document_types) is not bool
                or type(self.allow_ancestors) is not bool
                or not isinstance(self.timeouts, Timeouts)
                or type(self.max_response_bytes) is not int
                or not 1 <= self.max_response_bytes <= 8 * 1024**2
                or type(self.max_requests) is not int or not 1 <= self.max_requests <= 16):
            raise ValidationError('Некорректная ограниченная read-only конфигурация.')

    def authorize(self, method: str, url: str) -> tuple[str, str, bool]:
        """Return exact host/path/auth classification before DNS or body consumption."""
        if type(method) is not str or type(url) is not str:
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        if method == 'POST' and url in (AUTH_BASE + '/token/', AUTH_BASE + '/token/refresh/'):
            return 'lk.sarex.io', url[len('https://lk.sarex.io'):], True
        if method != 'GET':
            raise ApiError(ApiErrorCode.WRITES_DISABLED)
        if self.allow_document_types and url == DOCUMENTATION_BASE + '/v1/documents/types':
            return 'api.sarex.io', '/documentations/api/v1/documents/types', False
        if len(url) > 256:
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        match = re.fullmatch(re.escape(DOCUMENTATION_BASE)
                             + r'/v1/documents/([1-9][0-9]{0,18})(/ancestors)?', url)
        if (match is None or int(match[1]) not in self.document_ids
                or match[2] and not self.allow_ancestors):
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        return 'api.sarex.io', url[len('https://api.sarex.io'):], False


def load_read_only_policy(path: str | Path) -> ReadOnlyPolicy:
    path = checked_path(local_path(path), directory=False)
    if path.suffix != '.toml':
        raise ValidationError('Нужен явный TOML без секретов; .env не читается.')
    try:
        values = tomllib.loads(read_snapshot(path, MAX_CONFIG_BYTES).decode('utf-8'))
    except (ValueError, UnicodeError):
        raise ValidationError('Не удалось разобрать read-only TOML.') from None
    allowed = {'mode', 'document_ids', 'auth_base_url', 'documentation_base_url',
               'allow_document_types', 'allow_ancestors', 'timeouts', 'max_response_bytes',
               'max_requests'}
    if (values.keys() - allowed or values.pop('mode', None) != 'read-only'
            or not isinstance(values.get('document_ids'), list)
            or not {'auth_base_url', 'documentation_base_url'} <= values.keys()):
        raise ValidationError('Нужна явная read-only конфигурация без неизвестных полей/секретов.')
    values['document_ids'] = tuple(values['document_ids'])
    timeouts = values.get('timeouts', {})
    if (not isinstance(timeouts, dict) or timeouts.keys() - {'connect', 'read', 'total'}):
        raise ValidationError('Некорректные таймауты read-only конфигурации.')
    values['timeouts'] = Timeouts(**timeouts)
    return ReadOnlyPolicy(**values)
