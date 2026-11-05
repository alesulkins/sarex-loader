"""Portable regressions for Win32 ACL and share-mode decisions; no network."""
import sys
from types import SimpleNamespace

import pytest

from sarex_loader.safety import ValidationError
from sarex_loader.windows_journal_api import validate_acl

USER = 'S-1-5-21-123-500'
ADMIN = 'S-1-5-32-544'
ACES = [(0, USER), (0, 'S-1-5-18'), (0, ADMIN)]


def test_sqlite_sidecar_accepts_actual_admin_token_owner():
    validate_acl(ADMIN, ACES, USER, token_owner=ADMIN)
    validate_acl(USER, ACES, USER, token_owner=ADMIN)


@pytest.mark.parametrize('owner,token_owner,aces', [
    (ADMIN, USER, ACES),
    ('untrusted-group', 'untrusted-group', ACES),
    (ADMIN, ADMIN, ACES + [(0, 'S-1-1-0')]),
    (ADMIN, ADMIN, [(0, ADMIN)]),
    (USER, USER, []),
])
def test_owner_exception_never_bypasses_private_acl(owner, token_owner, aces):
    with pytest.raises(ValidationError):
        validate_acl(owner, aces, USER, token_owner=token_owner)


def test_directory_handle_participates_in_sharing_checks(tmp_path, monkeypatch):
    from sarex_loader import windows_files

    monkeypatch.setitem(sys.modules, 'msvcrt', SimpleNamespace())
    observed = []
    api = SimpleNamespace(CreateFileW=lambda *args: observed.append(args) or 42,
                          CloseHandle=lambda _: None)
    monkeypatch.setattr(windows_files, '_kernel', lambda: api)
    assert windows_files._handle(tmp_path, directory=True) == 42
    assert observed[0][1] & 1  # FILE_LIST_DIRECTORY; attributes alone do not lock renames.
    assert not observed[0][2] & 4  # FILE_SHARE_DELETE must remain absent.
