"""Local-only preparation of the single authorized independent test."""

import os

from sarex_loader.file_safety import directory_fd, read_snapshot
from sarex_loader.journal import Journal
from sarex_loader.safety import ValidationError
from sarex_loader.single_test_identity import EXCEL_OPERATION_ID
from sarex_loader.single_test_predecessor import independent_journal_path, predecessor_guard
from sarex_loader.single_test_transport import single_plan
from sarex_loader.synthetic_pdf import synthetic_pdf_bytes


def independent_pdf_path(config):
    if config.operation_id == EXCEL_OPERATION_ID:
        return (independent_journal_path(config.operation_id).parent / 'output'
                / f'excel-test-{config.operation_id}' / 'pdf' / config.filename)
    return independent_journal_path(config.operation_id).parent / 'output' / 'pdf' / config.filename


def verify_prepared(config):
    if (read_snapshot(independent_pdf_path(config), 8192)
            != synthetic_pdf_bytes(config.operation_id)):
        raise ValidationError('PREPARED_PDF_CHANGED')
    # Require a previously prepared journal, never silently replace a missing one.
    read_snapshot(independent_journal_path(config.operation_id) / 'journal.sqlite', 4 * 1024**2)


def _save_pdf(config):
    path = independent_pdf_path(config)
    root = independent_journal_path(config.operation_id).parent
    parents = [(root, 'output'), (root / 'output', 'pdf')]
    if config.operation_id == EXCEL_OPERATION_ID:
        leaf = f'excel-test-{config.operation_id}'
        parents = [(root, 'output'), (root / 'output', leaf), (root / 'output' / leaf, 'pdf')]
    for parent, name in parents:
        with directory_fd(parent) as directory:
            try:
                os.mkdir(name, 0o700, dir_fd=directory)
                os.fsync(directory)
            except FileExistsError:
                pass
    data = synthetic_pdf_bytes(config.operation_id)
    with directory_fd(path.parent) as directory:
        try:
            fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
        except FileExistsError:
            if read_snapshot(path, 8192) != data:
                raise ValidationError('PREPARED_PDF_CHANGED') from None
            return
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(directory)


def prepare_independent(config):
    config.draft()
    if config.operation_id is None:
        raise ValidationError('INDEPENDENT_CONFIG_REQUIRED')
    with predecessor_guard(config.operation_id) as evidence:
        directory = independent_journal_path(config.operation_id)
        if config.operation_id == EXCEL_OPERATION_ID:
            if directory.exists() or directory.is_symlink():
                raise ValidationError('EXCEL_TEST_ALREADY_REGISTERED_NO_RESET')
            _save_pdf(config)
            return {'status': 'EXCEL_PDF_PREPARED_REGISTRATION_REQUIRED',
                    'operation_id': config.operation_id, 'network_started': False,
                    'write_enabled': False, 'journal_created': False, 'predecessor': evidence}
        with Journal(directory, [directory.parent / 'src', directory.parent / 'output']) as journal:
            context, key, operations = single_plan(config)
            journal.register(context, operations)
            if journal.checkpoint(key)['state'] != 'PLANNED':
                raise ValidationError('INDEPENDENT_ALREADY_STARTED_NO_RESET')
            _save_pdf(config)
        return {'status': 'INDEPENDENT_TEST_PREPARED', 'operation_id': config.operation_id,
                'journal_state': 'PLANNED', 'network_started': False, 'write_enabled': False,
                'predecessor': evidence}


def register_excel_plan(config, binding, input_roots):
    """Explicit one-time registration only; never reopen/reset an existing request DB."""
    if config.operation_id != EXCEL_OPERATION_ID or type(binding) is not dict:
        raise ValidationError('NEW_EXCEL_OPERATION_REQUIRED')
    directory = independent_journal_path(config.operation_id)
    with predecessor_guard(config.operation_id):
        if read_snapshot(independent_pdf_path(config), 8192) != synthetic_pdf_bytes(
                config.operation_id):
            raise ValidationError('PREPARED_PDF_CHANGED')
        # Exclusive reservation also rejects a concurrent registration or any symlink.
        with directory_fd(directory.parent) as parent:
            try:
                os.mkdir(directory.name, 0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                raise ValidationError('EXCEL_TEST_ALREADY_REGISTERED_NO_RESET') from None
        with Journal(directory, input_roots) as journal:
            context, _, operations = single_plan(config, upload_context=binding)
            journal.register(context, operations)
    return {'status': 'EXCEL_PLAN_REGISTERED', 'journal_state': 'PLANNED',
            'network_enabled': False, 'write_enabled': False}
