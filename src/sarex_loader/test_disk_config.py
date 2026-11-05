"""Fixed, non-secret test-disk configuration. A saved ID never authorizes resource writes."""

import os
import tomllib
from pathlib import Path

from sarex_loader.api_models import valid_id
from sarex_loader.config import local_path
from sarex_loader.file_safety import directory_fd, read_snapshot
from sarex_loader.safety import ValidationError
from sarex_loader.test_target import TargetEvidence, validate_disk_id
from sarex_loader.test_target_policy import TEST_PARENT_ID, TEST_ROOT_ID


def _path(value):
    path = local_path(value).absolute()
    if path.suffix != '.toml':
        raise ValidationError('Нужен явный TOML конфигурации тестового диска.')
    return path


def check_new_config_path(value):
    path = _path(value)
    try:
        with directory_fd(path.parent) as parent:
            try:
                os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return path
    except OSError:
        raise ValidationError('Небезопасный или недоступный каталог конфигурации.') from None
    raise ValidationError('Конфигурация уже существует; перезапись запрещена.')


def save_verified_test_disk(value, evidence: TargetEvidence, expected_disk_id: str):
    """Called only after the current session's exact disk + ancestry checks succeed."""
    expected = validate_disk_id(expected_disk_id)
    if (type(evidence) is not TargetEvidence or evidence.expected_disk_matches is not True
            or evidence.disk_id != expected or type(evidence.chain_ids) is not tuple
            or not 2 <= len(evidence.chain_ids) <= 128
            or any(not valid_id(i) for i in evidence.chain_ids)
            or len(set(evidence.chain_ids)) != len(evidence.chain_ids)
            or evidence.chain_ids[0] != TEST_ROOT_ID or evidence.chain_ids[-1] != TEST_PARENT_ID):
        raise ValidationError('TEST_DISK_NOT_VERIFIED: нужны совпадение диска и проверенная ветка.')
    path = check_new_config_path(value)
    data = (f'mode = "fixed-test-disk"\nTEST_DISK_ID = "{expected}"\n'
            f'TEST_PARENT_ID = {TEST_PARENT_ID}\nTEST_ROOT_ID = {TEST_ROOT_ID}\n').encode()
    try:
        with directory_fd(path.parent) as parent:
            fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(parent)
    except OSError:
        # Preserve any partial artifact, never retry/overwrite it or create a second destination.
        raise ValidationError('CONFIG_SAVE_FAILED: автоматического повтора нет.') from None


def load_test_disk_config(value: str | Path) -> str:
    try:
        data = tomllib.loads(read_snapshot(_path(value), 8192).decode('utf-8'))
        if (set(data) != {'mode', 'TEST_DISK_ID', 'TEST_PARENT_ID', 'TEST_ROOT_ID'}
                or data['mode'] != 'fixed-test-disk'
                or type(data['TEST_PARENT_ID']) is not int
                or data['TEST_PARENT_ID'] != TEST_PARENT_ID
                or type(data['TEST_ROOT_ID']) is not int or data['TEST_ROOT_ID'] != TEST_ROOT_ID):
            raise ValueError
        return validate_disk_id(data['TEST_DISK_ID'])
    except Exception:
        raise ValidationError('Некорректная конфигурация фиксированного тестового диска.') from None
