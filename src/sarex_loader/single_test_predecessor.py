"""Read-only evidence for historical attempts; never resolves their UNKNOWN states."""

import hashlib
import os
import sqlite3
import stat
from contextlib import contextmanager

from sarex_loader.file_safety import directory_fd, read_snapshot
from sarex_loader.journal import CANDIDATE_SCHEMA, SCHEMA, canonical, fingerprint
from sarex_loader.process_lock import lock_file
from sarex_loader.response_candidates import safe_bundle_id
from sarex_loader.safety import ValidationError
from sarex_loader.single_test_config import SingleTestConfig, single_journal_path
from sarex_loader.single_test_identity import (
    EXCEL_OPERATION_ID,
    INDEPENDENT_OPERATION_ID,
    OLD_DISK_ID,
    THIRD_OPERATION_ID,
    validate_operation_id,
)

MAX_PREDECESSOR_BYTES = 4 * 1024**2


def independent_journal_path(operation_id=INDEPENDENT_OPERATION_ID):
    validate_operation_id(operation_id)
    if operation_id is None:
        raise ValidationError('INDEPENDENT_CONFIG_REQUIRED')
    return single_journal_path().parent / f'.single-test-{operation_id}'


def predecessor_plan():
    from sarex_loader.single_test_transport import single_plan
    context, _, _ = single_plan(SingleTestConfig('pdf', 'pdf', '2026-10-01T12:00:00+03:00'))
    context['disk_id'] = context['draft']['disk_id'] = OLD_DISK_ID
    key = fingerprint(context)
    return context, key, {key: {'status': 'LOCAL_MATCH', **context}}


def second_plan():
    from sarex_loader.single_test_transport import single_plan
    return single_plan(SingleTestConfig('pdf', 'pdf', '2026-10-01T12:00:00+03:00',
                                       INDEPENDENT_OPERATION_ID))


def predecessor_reference(operation_id=None):
    validate_operation_id(operation_id)
    if operation_id == EXCEL_OPERATION_ID:
        return {'previous': predecessor_reference(THIRD_OPERATION_ID),
                'third_document_id': 7978396, 'third_state': 'OUTCOME_UNKNOWN',
                'decision': 'EXPLICIT_EXCEL_PLAN_REGISTRATION_REQUIRED',
                'artifact_assessment': 'THREE_PRIOR_OUTCOMES_UNRESOLVED'}
    if operation_id == THIRD_OPERATION_ID:
        return {'attempts': [predecessor_reference(), {
            'operation_key': second_plan()[1], 'state': 'OUTCOME_UNKNOWN',
            'phase': 'CREATE_BUNDLE', 'reported_http_status': 200,
            'http_evidence': 'USER_REPORT', 'bundle_id_recorded': False,
            'artifact_assessment': 'SERVER_ARTIFACTS_NOT_EXCLUDED',
        }], 'decision': 'THIRD_INDEPENDENT_TEST_AUTHORIZED_NOT_A_RETRY',
                'artifact_assessment': 'TWO_PRIOR_ARTIFACTS_NOT_EXCLUDED'}
    return {'operation_key': predecessor_plan()[1], 'state': 'OUTCOME_UNKNOWN',
            'phase': 'CREATE_BUNDLE', 'reported_http_status': 404,
            'http_evidence': 'USER_REPORT', 'bundle_id_received': False,
            'artifact_assessment': 'SERVER_ARTIFACTS_NOT_EXCLUDED',
            'decision': 'ONE_INDEPENDENT_TEST_AUTHORIZED_NOT_A_RETRY'}


def _inspect(path, plan=None):
    # Deserialize a bounded snapshot: SQLite never opens the historical file for
    # recovery, writes, WAL or rollback. A hot/unknown sidecar blocks inspection.
    rollback = path / 'journal.sqlite-journal'
    if rollback.exists():
        sidecar = read_snapshot(rollback, MAX_PREDECESSOR_BYTES)
        if sidecar and (len(sidecar) < 28 or sidecar[:28] != b'\0' * 28):
            raise ValidationError('PREDECESSOR_HOT_JOURNAL')
    raw = read_snapshot(path / 'journal.sqlite', MAX_PREDECESSOR_BYTES)
    db = sqlite3.connect(':memory:')
    try:
        db.deserialize(raw)
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        schema = dict(db.execute("SELECT name,sql FROM sqlite_master WHERE sql IS NOT NULL"))
        if schema != SCHEMA or db.execute('PRAGMA quick_check').fetchone() != ('ok',):
            raise ValidationError('PREDECESSOR_SCHEMA_MISMATCH')
        context, key, operations = predecessor_plan() if plan is None else plan
        if dict(db.execute('SELECT key,value FROM meta')) != {
            'schema': '1', 'context': fingerprint(context)
        }:
            raise ValidationError('PREDECESSOR_PLAN_MISMATCH')
        if list(db.execute('SELECT * FROM operations')) != [
            (key, canonical(operations[key]), 'OUTCOME_UNKNOWN', 'CREATE_BUNDLE',
             None, None, 'UNVERIFIED')
        ]:
            raise ValidationError('PREDECESSOR_STATE_MISMATCH')
    finally:
        db.close()
    return hashlib.sha256(raw).hexdigest()


@contextmanager
def _guard(path, plan, reference, inspector=None):
    inspect = _inspect if inspector is None else inspector
    try:
        with directory_fd(path) as directory:
            info = os.fstat(directory)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValidationError('PREDECESSOR_UNSAFE_DIRECTORY')
            allowed = {'journal.sqlite', 'journal.sqlite-journal', 'process.lock'}
            with os.scandir(directory) as entries:
                for entry in entries:
                    info = entry.stat(follow_symlinks=False)
                    if (entry.name not in allowed or not stat.S_ISREG(info.st_mode)
                            or info.st_nlink != 1 or info.st_uid != os.getuid()
                            or stat.S_IMODE(info.st_mode) != 0o600):
                        raise ValidationError('PREDECESSOR_UNSAFE_FILE')
            lock = os.open('process.lock', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            try:
                lock_file(lock, shared=True)
                before = inspect(path, plan)
                try:
                    yield {**reference, 'journal_sha256': before}
                finally:
                    if inspect(path, plan) != before:
                        raise ValidationError('PREDECESSOR_CHANGED')
            finally:
                os.close(lock)
    except (OSError, sqlite3.Error):
        raise ValidationError('PREDECESSOR_UNAVAILABLE_OR_INVALID') from None


@contextmanager
def predecessor_guard(operation_id=None):
    """Hold shared locks on ALL predecessors, including during failure unwinding."""
    validate_operation_id(operation_id)
    if operation_id == EXCEL_OPERATION_ID:
        third = SingleTestConfig('pdf', 'pdf', '2026-11-03T12:00:00+03:00', THIRD_OPERATION_ID)
        with created_document_evidence(third, 7978396):
            yield predecessor_reference(operation_id)
        return
    with _guard(single_journal_path(), predecessor_plan(), predecessor_reference()) as first:
        if operation_id != THIRD_OPERATION_ID:
            yield first
        else:
            reference = predecessor_reference(operation_id)
            with _guard(independent_journal_path(), second_plan(),
                        reference['attempts'][1]) as second:
                yield {**reference, 'attempts': [first, second]}


@contextmanager
def created_document_evidence(config, document_id, *, upload_context=None):
    """Candidate/checkpoint evidence, RAM SQLite only; never run Journal recovery."""
    from sarex_loader.api_models import valid_id
    from sarex_loader.single_test_transport import single_plan

    legacy = config.operation_id == THIRD_OPERATION_ID and upload_context is None
    if (not valid_id(document_id) or legacy and document_id != 7978396
            or not legacy and (config.operation_id != EXCEL_OPERATION_ID
                               or type(upload_context) is not dict)):
        raise ValidationError('CREATED_DOCUMENT_SCOPE_MISMATCH')
    evidence = {}
    def inspect(path, plan):
        rollback = path / 'journal.sqlite-journal'
        if rollback.exists():
            sidecar = read_snapshot(rollback, MAX_PREDECESSOR_BYTES)
            if sidecar and (len(sidecar) < 28 or sidecar[:28] != b'\0' * 28):
                raise ValidationError('PREDECESSOR_HOT_JOURNAL')
        raw = read_snapshot(path / 'journal.sqlite', MAX_PREDECESSOR_BYTES)
        db = sqlite3.connect(':memory:')
        try:
            db.deserialize(raw)
            db.execute('PRAGMA query_only=ON')
            db.execute('PRAGMA trusted_schema=OFF')
            if (dict(db.execute('SELECT name,sql FROM sqlite_master WHERE sql IS NOT NULL'))
                    != {**SCHEMA, 'response_candidates': CANDIDATE_SCHEMA}
                    or db.execute('PRAGMA quick_check').fetchone() != ('ok',)):
                raise ValidationError('RECOVERY_SCHEMA_MISMATCH')
            context, key, operations = plan
            if dict(db.execute('SELECT key,value FROM meta')) != {
                    'schema': '2', 'context': fingerprint(context)}:
                raise ValidationError('RECOVERY_PLAN_MISMATCH')
            rows = db.execute('SELECT * FROM operations').fetchall()
            if len(rows) != 1 or not safe_bundle_id(rows[0][4]):
                raise ValidationError('RECOVERY_CHECKPOINT_MISMATCH')
            bundle = rows[0][4]
            state = rows[0][2]
            if (state not in ({'OUTCOME_UNKNOWN'} if legacy else {'OUTCOME_UNKNOWN', 'ATTACHED'})
                    or rows != [(key, canonical(operations[key]), state, 'CREATE_DOCUMENT', bundle,
                                 document_id if state == 'ATTACHED' else None, 'UNVERIFIED')]):
                raise ValidationError('RECOVERY_CHECKPOINT_MISMATCH')
            candidates = db.execute('SELECT * FROM response_candidates ORDER BY phase').fetchall()
            if candidates != [(key, 'CREATE_BUNDLE', bundle, None),
                              (key, 'CREATE_DOCUMENT', None, document_id),
                              (key, 'UPLOAD_FINISH', bundle, None)]:
                raise ValidationError('RECOVERY_CANDIDATES_MISMATCH')
            evidence.update(bundle_id=bundle, document_id=document_id)
            if not legacy:
                evidence['journal_state'] = state
        finally:
            db.close()
        return hashlib.sha256(raw).hexdigest()
    with predecessor_guard(config.operation_id), _guard(
            independent_journal_path(config.operation_id),
            single_plan(config, upload_context=upload_context), {}, inspect):
        yield dict(evidence)
