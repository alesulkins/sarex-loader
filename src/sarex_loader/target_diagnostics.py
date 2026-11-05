"""Read-only metadata diagnosis. No raw fields, paths, names or inferred disk inheritance."""

import uuid
from collections import Counter

from sarex_loader.api_models import ApiError
from sarex_loader.gateway_models import _path
from sarex_loader.safety import ValidationError
from sarex_loader.test_target import disk_id_format, validate_disk_id, verify_target
from sarex_loader.test_target_policy import TEST_PARENT_ID, TEST_ROOT_ID


def _id_path(document):
    # Reuse the strict offline grammar only as a diagnostic hypothesis for Documentation.
    # Its validity for Gateway does NOT make it a documented Documentation contract.
    ids = _path(document.path)
    if ids[-1] != document.id:
        raise ValueError
    return ids


def _path_state(document):
    if document.path is None:
        return 'MISSING'
    if document.path == '':
        return 'EMPTY'
    try:
        _id_path(document)
    except (ApiError, ValueError):
        return 'NOT_SELF_TERMINATED_ID_PATH'
    return 'SELF_TERMINATED_DOT_IDS'


def assess_id_paths(parent, root, ancestors):
    """Corroborate the proposed root-to-self grammar across ALL returned ancestors.

    Result is diagnostic only and never authorizes writes or promotes TargetEvidence.
    Empty folders are unknown; contradictory nonempty in-scope edges are rejected.
    """
    if (parent.id != TEST_PARENT_ID or root.id != TEST_ROOT_ID
            or not parent.is_folder or not root.is_folder):
        return 'INCONSISTENT'
    nodes = {d.id: d for d in ancestors}
    if len(nodes) != len(ancestors) or TEST_ROOT_ID not in nodes:
        return 'INCONSISTENT'
    for d in (parent, root):
        if d.id in nodes and nodes[d.id] != d:
            return 'INCONSISTENT'
        nodes[d.id] = d
    try:
        target_path = _id_path(parent)
        if TEST_ROOT_ID not in target_path[:-1] or set(nodes) != set(target_path):
            return 'INCONSISTENT'
        for position, identifier in enumerate(target_path):
            node = nodes[identifier]
            if node.is_folder is not True or _id_path(node) != target_path[:position + 1]:
                return 'INCONSISTENT'
            for child in node.folders or ():
                if child in nodes and (
                        position + 1 >= len(target_path) or child != target_path[position + 1]):
                    return 'INCONSISTENT'
    except (ApiError, ValueError):
        return 'INSUFFICIENT_OR_UNSUPPORTED'
    return 'CONSISTENT_ID_PATHS_NOT_AUTHORIZATION'


def diagnose_target(client, *, expected_disk_id=None):
    report, _ = diagnose_target_result(client, expected_disk_id=expected_disk_id)
    return report


def diagnose_target_result(client, *, expected_disk_id=None):
    """Return evidence separately so only an actual successful verification can pin a disk."""
    if expected_disk_id is not None:
        validate_disk_id(expected_disk_id)
    parent = client.get_document(TEST_PARENT_ID)
    # Do not expand the read scope based on untrusted IDs or malformed target identity.
    if parent.id != TEST_PARENT_ID or parent.is_folder is not True:
        raise ValidationError('TARGET_UNVERIFIED: целевой объект не папка.')
    root = client.get_document(TEST_ROOT_ID)
    ancestors = client.get_ancestors(TEST_PARENT_ID)
    report = {
        'mode': 'TEST_TARGET_METADATA_DIAGNOSTIC',
        'parent_id': TEST_PARENT_ID, 'allowed_root_id': TEST_ROOT_ID,
        'disk_fields': {'target': disk_id_format(parent.disk_id),
                        'root': disk_id_format(root.disk_id),
                        'ancestors': dict(sorted(Counter(disk_id_format(d.disk_id)
                                                        for d in ancestors).items()))},
        'path_fields': {'target': _path_state(parent), 'root': _path_state(root),
                        'ancestors': dict(sorted(Counter(_path_state(d)
                                                        for d in ancestors).items()))},
        'ancestor_count': len(ancestors),
        'root_present_in_ancestors': any(d.id == TEST_ROOT_ID for d in ancestors),
        'folders_fields': {'root_count': None if root.folders is None else len(root.folders),
                           'target_count': None if parent.folders is None else len(parent.folders),
                           'ancestors_missing': sum(d.folders is None for d in ancestors),
                           'ancestors_empty': sum(d.folders == () for d in ancestors)},
        'path_assessment': assess_id_paths(parent, root, ancestors),
        'path_contract_confirmed': False,
        'write_enabled': False, 'live_upload_ready': False,
    }
    # Only a UUID from the TARGET's own field may be reported as an observation.
    # Root/ancestor IDs or caller-provided expectations never fill a missing target field.
    observed = (str(uuid.UUID(parent.disk_id)) if disk_id_format(parent.disk_id) in
                {'CANONICAL_UUID', 'UUID_HEX_CASE'} else None)
    report['observed_target_disk_id'] = observed
    report['expected_target_disk_match'] = (
        observed == expected_disk_id if observed is not None and expected_disk_id is not None
        else None)
    evidence = None
    try:
        evidence = verify_target(parent, root, ancestors, expected_disk_id=expected_disk_id)
    except ValidationError as exc:
        # Explicit allowlist: never copy exception prose or untrusted values into output.
        prefix = str(exc).split(':', 1)[0]
        report['verification'] = prefix if prefix in {
            'DISK_UNVERIFIED', 'DISK_MISMATCH', 'ANCESTRY_UNVERIFIED',
            'ANCESTRY_CONFLICT', 'TARGET_UNVERIFIED'} else 'TARGET_UNVERIFIED'
        report['verified'] = False
    else:
        report['verification'] = 'TARGET_METADATA_VERIFIED'
        report['verified'] = True
        report['evidence'] = evidence.summary()
    return report, evidence
