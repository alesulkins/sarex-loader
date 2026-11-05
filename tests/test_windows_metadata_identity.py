"""Windows DirEntry zeros must never turn unrelated PDFs into hard-link duplicates."""
import os
from contextlib import nullcontext

from sarex_loader import windows_files


def test_scanner_uses_fresh_stat_not_direntry_cache(tmp_path, monkeypatch):
    names = ['2026-01-02-тест-001.pdf', '2026-01-02-тест-999.pdf']
    for name in names:
        (tmp_path / name).write_bytes(b'synthetic')
    real_scandir = os.scandir

    class Entry:
        def __init__(self, item):
            self.name, self.path = item.name, item.path

        def stat(self, **kwargs):
            raise AssertionError('Windows DirEntry stat cannot identify files')

    class Entries:
        def __enter__(self):
            with real_scandir(tmp_path) as entries:
                return iter([Entry(entry) for entry in entries])

        def __exit__(self, *args):
            pass

    monkeypatch.setattr(windows_files, 'locked_directory', lambda _: nullcontext())
    monkeypatch.setattr(windows_files.os, 'scandir', lambda _: Entries())
    entries = list(windows_files.scan_metadata(tmp_path, 100, 1024))
    assert all(entry['reason'] is None for entry in entries)
    assert len({tuple(entry['identity'][:2]) for entry in entries}) == 2


def test_real_hardlinks_keep_same_identity(tmp_path, monkeypatch):
    source = tmp_path / '2026-01-02-тест-001.pdf'
    source.write_bytes(b'synthetic')
    os.link(source, tmp_path / '2026-01-02-тест-002.pdf')
    monkeypatch.setattr(windows_files, 'locked_directory', lambda _: nullcontext())
    entries = list(windows_files.scan_metadata(tmp_path, 100, 1024))
    assert all(entry['reason'] is None for entry in entries)
    assert len({tuple(entry['identity'][:2]) for entry in entries}) == 1
