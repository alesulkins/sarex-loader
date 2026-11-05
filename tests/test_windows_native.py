"""Execute on a real Windows host; skips here are not proof of Windows acceptance."""
import os
from pathlib import Path

import pytest

from sarex_loader.file_safety import read_snapshot
from sarex_loader.folder_creation import FolderSimulationJournal
from sarex_loader.pdf_scan import scan_pdfs
from sarex_loader.reports import _write_bundle
from sarex_loader.safety import ValidationError

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Требуется настоящая Windows')


def test_native_read_report_no_overwrite_and_unicode(tmp_path):
    root = tmp_path / 'вход'
    root.mkdir()
    source = root / 'реестр.txt'
    source.write_bytes('Пример'.encode())
    assert read_snapshot(source, 100) == 'Пример'.encode()
    output = tmp_path / 'отчёт'
    _write_bundle(output, {'таблица.csv': 'PDF;Причина\n'.encode('utf-8-sig')}, [root])
    assert (output / 'COMPLETE.json').is_file()
    assert (output / 'таблица.csv').read_bytes().startswith(b'\xef\xbb\xbf')
    with pytest.raises(ValidationError):
        _write_bundle(output, {'таблица.csv': b'overwrite'}, [root])
    assert source.read_bytes() == 'Пример'.encode()


def test_native_metadata_does_not_open_pdf(tmp_path, monkeypatch):
    path = tmp_path / '2026-01-02-тест-1.pdf'
    path.write_bytes(b'%PDF-synthetic')
    original = Path.open

    def guarded(path, *args, **kwargs):
        if path.suffix == '.pdf':
            raise AssertionError('Содержимое PDF читать нельзя')
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'open', guarded)
    files = list(scan_pdfs(tmp_path, metadata_only=True))
    assert len(files) == 1 and files[0]['reason'] is None


def test_native_parent_handle_blocks_rename(tmp_path):
    from sarex_loader.windows_files import locked_directory

    folder = tmp_path / 'папка'
    folder.mkdir()
    with locked_directory(folder), pytest.raises(OSError):
        folder.rename(tmp_path / 'переименовано')


def test_native_sqlite_simulation_lock_and_unknown(tmp_path):
    path = tmp_path / 'folder-simulation.sqlite3'
    first = FolderSimulationJournal(path)
    try:
        first.record('key', 'OUTCOME_UNKNOWN', {'candidate_id': 123})
        with pytest.raises(ValidationError):
            FolderSimulationJournal(path)
    finally:
        first.close()
    again = FolderSimulationJournal(path)
    try:
        assert again.state('key') == 'OUTCOME_UNKNOWN'
    finally:
        again.close()


def test_native_upload_journal_crash_resume_lock_and_reader():
    from tests.windows_journal_probe import run_probe

    result = run_probe()
    assert result['platform'] == 'Windows'
    assert result['checks']['replay_effects'] == 0
    assert result['checks']['crash_resume_unknown']


def test_native_upload_journal_blocks_rename_and_checks_acl(tmp_path):
    from sarex_loader.journal import Journal
    from sarex_loader.windows_journal_api import WindowsJournalAPI

    source = tmp_path / 'вход'
    source.mkdir()
    path = tmp_path / 'приватный журнал'
    with Journal(path, [source]):
        api = WindowsJournalAPI()
        api.inspect(path, directory=True)
        api.inspect(path / 'journal.sqlite')
        with pytest.raises(OSError):
            path.rename(tmp_path / 'замена')
        with pytest.raises(OSError):
            (path / 'journal.sqlite').rename(path / 'переименовано.sqlite')
