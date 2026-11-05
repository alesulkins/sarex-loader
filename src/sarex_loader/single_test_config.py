"""Explicit Bundle fields; target/disk/source bytes cannot be overridden by configuration."""

import tomllib
from dataclasses import dataclass
from pathlib import Path

from sarex_loader.api_upload_models import BundleDraft
from sarex_loader.config import local_path
from sarex_loader.file_safety import read_snapshot
from sarex_loader.safety import ValidationError
from sarex_loader.single_test_identity import independent_filename, validate_operation_id
from sarex_loader.single_test_scope import TEST_DISK_ID, TEST_FILENAME


@dataclass(frozen=True, repr=False)
class SingleTestConfig:
    document_type: str
    key: str
    date: str
    operation_id: str | None = None

    @property
    def filename(self):
        validate_operation_id(self.operation_id)
        return (TEST_FILENAME if self.operation_id is None
                else independent_filename(self.operation_id))

    def draft(self):
        return BundleDraft(TEST_DISK_ID, self.document_type, self.key, self.filename, self.date)


def load_single_test_config(value):
    try:
        path = local_path(value).absolute()
        if path.suffix != '.toml':
            raise ValueError
        values = tomllib.loads(read_snapshot(path, 8192).decode())
        required = {'mode', 'document_type', 'key', 'date'}
        if (set(values) not in (required, required | {'operation_id'})
                or values.pop('mode') != 'single-synthetic-test'):
            raise ValueError
        config = SingleTestConfig(**values)
        config.draft()
        return config
    except Exception:
        raise ValidationError(
            'Некорректная конфигурация одиночного синтетического теста.') from None


def single_journal_path():
    # Stable across current directories and invocations: no CLI "new journal" escape.
    return Path(__file__).resolve().parents[2] / '.single-test-journal'
