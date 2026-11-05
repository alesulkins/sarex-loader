"""Backup and atomic URL-only replacement. No network or remote journal transitions."""

import hashlib
import json
import os
import stat
from pathlib import Path
from uuid import uuid4

from sarex_loader.config import checked_path
from sarex_loader.excel_copy import make_url_copy
from sarex_loader.file_safety import read_snapshot
from sarex_loader.pdf_scan import identity
from sarex_loader.process_lock import lock_file
from sarex_loader.safety import ValidationError


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _sync_directory(path):
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _new_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def commit_urls(path, snapshot, updates, *, backup_dir, approved_document_ids=None):
    """Commit to exactly the supplied workbook; the snapshot also permits safe retry.

    If replacement succeeded but receipt creation failed, retrying with the SAME
    snapshot and updates recognizes the target hash and performs no replacement.
    SQLite remote states remain GET evidence, never evidence of Excel persistence.
    """
    path = checked_path(Path(path), directory=False)
    backup_dir = checked_path(Path(backup_dir), directory=True)
    if backup_dir == path.parent or backup_dir.is_relative_to(path):
        raise ValidationError("Для резервных копий нужен отдельный каталог.")
    limit = max(len(snapshot) * 2, 1024 * 1024)
    before_sha = _sha(snapshot)
    result = make_url_copy(
        snapshot, before_sha, updates, approved_document_ids=approved_document_ids
    )
    if not updates:
        result = snapshot  # Zero URLs must not even reserialize the ZIP container.
    after_sha = _sha(result)
    receipt = {
        "input_file": str(path),
        "before_sha256": before_sha,
        "after_sha256": after_sha,
        "urls_written": len(updates),
        "disk_verified": False,
        "backup_file": None,
        "already_saved": False,
    }
    lock_path = path.with_name("." + path.name + ".sarex-lock")
    if lock_path.is_symlink():
        raise ValidationError("Небезопасный файл блокировки Excel.")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    temporary = path.with_name("." + path.name + "." + uuid4().hex + ".tmp")
    try:
        lock_file(fd)
        if path.with_name("~$" + path.name).exists():
            raise ValidationError("Excel открыт в другом приложении. Закройте книгу и повторите.")
        info = path.lstat()
        if info.st_nlink != 1 or not stat.S_ISREG(info.st_mode):
            raise ValidationError(
                "Для записи нужна обычная книга без ссылок и дополнительных имён."
            )
        current = read_snapshot(path, limit)
        if _sha(current) == after_sha:
            receipt.update(disk_verified=True, already_saved=True, urls_written=0)
            return receipt
        if current != snapshot:
            raise ValidationError(
                "Excel изменился после проверки. Нужен новый план; запись отменена."
            )
        if not info.st_mode & 0o222 or not os.access(path, os.W_OK):
            raise ValidationError("Excel недоступен для записи. Исходная книга сохранена.")
        backup = backup_dir / (path.stem + "-" + uuid4().hex + ".xlsx")
        _new_file(backup, snapshot)
        _sync_directory(backup_dir)
        if read_snapshot(backup, limit) != snapshot:
            raise ValidationError("Не удалось подтвердить резервную копию Excel.")
        receipt["backup_file"] = str(backup)
        intent = backup.with_suffix(".intent.json")
        _new_file(intent, json.dumps(receipt, ensure_ascii=False, indent=2).encode())
        _sync_directory(backup_dir)
        _new_file(temporary, result)
        os.chmod(temporary, stat.S_IMODE(info.st_mode))
        if (
            path.with_name("~$" + path.name).exists()
            or identity(path.lstat()) != identity(info)
            or read_snapshot(path, limit) != snapshot
        ):
            raise ValidationError("Excel открыт или изменился перед сохранением; запись отменена.")
        os.replace(temporary, path)
        _sync_directory(path.parent)
        if read_snapshot(path, limit) != result:
            raise ValidationError(
                "Сохранение Excel не подтверждено. Сохраните журнал и резервную копию."
            )
        receipt["disk_verified"] = True
        _new_file(
            backup.with_suffix(".saved.json"),
            json.dumps(receipt, ensure_ascii=False, indent=2).encode(),
        )
        _sync_directory(backup_dir)
        return receipt
    except OSError:
        raise ValidationError(
            "Не удалось безопасно сохранить Excel. Закройте книгу, проверьте "
            "права и место на диске. Резервные копии и журнал не удаляйте."
        ) from None
    finally:
        os.close(fd)
        # Never unlink the stable lock: a waiting process may still hold its inode.
        temporary.unlink(missing_ok=True)
