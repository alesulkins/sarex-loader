"""POSIX descriptor-based access; do not follow links in any path component."""

import os
import stat
from contextlib import contextmanager
from pathlib import Path

from sarex_loader.config import local_path
from sarex_loader.safety import ValidationError


@contextmanager
def directory_fd(path: Path):
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise ValidationError("Безопасный доступ через dir_fd недоступен на этой ОС.")
    path = local_path(path).absolute()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_snapshot(path: Path, limit: int) -> bytes:
    """Read bounded bytes from a regular file and detect concurrent modification."""
    try:
        if os.name == 'nt':
            from sarex_loader.windows_files import read_snapshot as windows_read

            return windows_read(path, limit)
        with directory_fd(path.parent) as parent:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(fd, "rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                    raise ValidationError("Вход не является обычным файлом в пределах лимита.")
                data = stream.read(limit + 1)
                after = os.fstat(stream.fileno())
                if len(data) > limit or _file_identity(before) != _file_identity(after):
                    raise ValidationError("Вход превышает лимит или изменился при чтении.")
                return data
    except OSError:
        raise ValidationError("Не удалось безопасно прочитать локальный файл.") from None
