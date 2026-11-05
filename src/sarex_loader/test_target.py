"""Fail-closed ancestry evidence using Document.folders edges, not names or guessed path syntax."""

import re
import uuid
from dataclasses import dataclass, replace

from sarex_loader.api_models import Document, valid_id
from sarex_loader.safety import ValidationError
from sarex_loader.test_target_policy import TEST_PARENT_ID, TEST_ROOT_ID


def disk_id_format(value):
    """Only a fixed classification escapes this function, never an invalid value."""
    if value is None:
        return 'MISSING'
    if type(value) is not str:
        return 'INVALID_TYPE'
    if not value:
        return 'EMPTY'
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        return 'NOT_UUID'
    if parsed.int == 0:
        return 'ZERO_UUID'
    if str(parsed) == value:
        return 'CANONICAL_UUID'
    if re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', value):
        return 'UUID_HEX_CASE'
    return 'NON_CANONICAL_UUID'


def validate_disk_id(value):
    classification = disk_id_format(value)
    if classification != 'CANONICAL_UUID':
        raise ValidationError('DISK_UNVERIFIED: ' + classification
                              + '; нужен явный канонический UUID диска.')
    return value


def _canonical_disk(document):
    # UUID hex case does not change its 128-bit identity. No trim, inheritance,
    # compact/URN parsing, Gateway fallback or substitution from another document.
    if type(document) is Document and disk_id_format(document.disk_id) == 'UUID_HEX_CASE':
        return replace(document, disk_id=str(uuid.UUID(document.disk_id)))
    return document


@dataclass(frozen=True, repr=False)
class TargetEvidence:
    disk_id: str
    chain_ids: tuple[int, ...]
    expected_disk_matches: bool

    def summary(self):
        return {'status': 'TARGET_METADATA_VERIFIED', 'parent_id': TEST_PARENT_ID,
                'allowed_root_id': TEST_ROOT_ID, 'disk_id': self.disk_id,
                'chain_ids': list(self.chain_ids),
                'expected_disk_matches': self.expected_disk_matches,
                'write_enabled': False, 'live_upload_ready': False}


def verify_target(parent: Document, root: Document, ancestors: tuple[Document, ...], *,
                  expected_disk_id: str | None = None) -> TargetEvidence:
    """Require an unambiguous folder-ID edge chain corroborated by /ancestors.

    Documentation.path has no declared encoding; Gateway's dot-path convention is
    deliberately NOT assumed here. Missing folders edges mean insufficient evidence.
    The result is an observation, not a reusable authorization capability for writes.
    """
    if expected_disk_id is not None:
        validate_disk_id(expected_disk_id)
    parent, root = _canonical_disk(parent), _canonical_disk(root)
    if type(ancestors) is tuple:
        ancestors = tuple(_canonical_disk(d) for d in ancestors)
    if (type(parent) is not Document or type(root) is not Document
            or parent.id != TEST_PARENT_ID or root.id != TEST_ROOT_ID
            or parent.is_folder is not True or root.is_folder is not True
            or type(ancestors) is not tuple or not 1 <= len(ancestors) <= 128
            or any(type(d) is not Document or not valid_id(d.id) for d in ancestors)):
        raise ValidationError('TARGET_UNVERIFIED: неверные метаданные тестовой папки.')
    disk = validate_disk_id(parent.disk_id)
    if root.disk_id != disk or expected_disk_id is not None and expected_disk_id != disk:
        raise ValidationError('DISK_MISMATCH: диск не подтверждён.')
    nodes = {d.id: d for d in ancestors}
    if len(nodes) != len(ancestors) or TEST_ROOT_ID not in nodes:
        raise ValidationError('ANCESTRY_UNVERIFIED: корень не подтверждён среди предков.')
    # A changed folder between the separate reads must not be silently reconciled.
    for d in (root, parent):
        if d.id in nodes and nodes[d.id] != d:
            raise ValidationError('ANCESTRY_CONFLICT: метаданные между GET различаются.')
        nodes[d.id] = d
    parents = {}
    for node in nodes.values():
        if node.is_folder is not True:
            raise ValidationError('ANCESTRY_UNVERIFIED: предок не является папкой.')
        for child in node.folders or ():
            if not valid_id(child) or child == node.id:
                raise ValidationError('ANCESTRY_CONFLICT: некорректная связь папок.')
            if child not in nodes:
                continue  # Siblings are not proof nodes and are never queried.
            if child in parents:
                raise ValidationError('ANCESTRY_CONFLICT: несколько связей с одним потомком.')
            parents[child] = node.id
    # Reject cycles anywhere in the returned induced ancestry graph in linear time.
    done = set()
    for identifier in nodes:
        trail = set()
        current = identifier
        while current in nodes and current not in done:
            if current in trail:
                raise ValidationError('ANCESTRY_CONFLICT: цикл связей папок.')
            trail.add(current)
            current = parents.get(current)
        done.update(trail)
    chain, current = [], TEST_PARENT_ID
    while True:
        node = nodes[current]
        if node.disk_id != disk:
            raise ValidationError('DISK_MISMATCH: разный или неизвестный диск в цепочке.')
        chain.append(current)
        if current == TEST_ROOT_ID:
            break
        current = parents.get(current)
        if current is None:
            raise ValidationError('ANCESTRY_UNVERIFIED: нет полной цепочки связей до 99-Тест.')
    # An ancestors response may contain higher roots; every other node must be on the
    # same verified chain. Disconnected or extra alleged ancestors fail closed.
    current = parents.get(TEST_ROOT_ID)
    while current is not None:
        chain.append(current)
        current = parents.get(current)
    if set(chain) != set(nodes):
        raise ValidationError('ANCESTRY_CONFLICT: несогласованный набор предков.')
    branch = chain[:chain.index(TEST_ROOT_ID) + 1]
    return TargetEvidence(disk, tuple(reversed(branch)), expected_disk_id is not None)


def inspect_target(client, *, expected_disk_id=None):
    if expected_disk_id is not None:
        validate_disk_id(expected_disk_id)  # Before the first request.
    parent = _canonical_disk(client.get_document(TEST_PARENT_ID))
    if not parent.is_folder or parent.id != TEST_PARENT_ID:
        raise ValidationError('TARGET_UNVERIFIED: целевой объект не папка.')
    disk = validate_disk_id(parent.disk_id)
    if expected_disk_id is not None and disk != expected_disk_id:
        raise ValidationError('DISK_MISMATCH: ожидался другой диск.')
    root = client.get_document(TEST_ROOT_ID)
    ancestors = client.get_ancestors(TEST_PARENT_ID)
    return verify_target(parent, root, ancestors, expected_disk_id=expected_disk_id)
