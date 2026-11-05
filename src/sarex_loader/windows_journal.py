"""Windows filesystem guards for Journal; the SQLite schema/state machine stay shared."""

import os

from sarex_loader.safety import ValidationError
from sarex_loader.windows_journal_api import WindowsJournalAPI


class WindowsJournalStorage:
    def __init__(self, path, stack, max_bytes, *, api=None, read_only=False):
        self.path, self.max_bytes = path, max_bytes
        self.api = api or WindowsJournalAPI()
        for parent in (*reversed(path.parent.parents), path.parent):
            stack.callback(self.api.close, self.api.directory(parent))
        if not read_only:
            self.api.create_directory(path)
        directory = self.api.directory(path)
        stack.callback(self.api.close, directory)
        self.api.private(directory)
        self.identity = self.api.info(directory).identity
        self.check_files()
        # Share mode zero holds the one-writer lock across the entire process lifetime.
        lock = self.api.open_private(path / 'process.lock', exclusive=True, create=not read_only)
        stack.callback(os.close, lock)
        self.check_files()
        self.new = not (path / 'journal.sqlite').exists()
        self.db_fd = self.api.open_private(path / 'journal.sqlite', create=not read_only,
                                           read_only=read_only)
        stack.callback(os.close, self.db_fd)
        self.db_identity = self.api.inspect(path / 'journal.sqlite').identity
        self.verify()

    def check_files(self):
        allowed = {'process.lock', 'journal.sqlite', 'journal.sqlite-journal'}
        with os.scandir(self.path) as entries:
            for entry in entries:
                if entry.name not in allowed:
                    raise ValidationError('Неожиданный файл в каталоге журнала Windows.')
                info = self.api.inspect(self.path / entry.name)
                if info.size > self.max_bytes:
                    raise ValidationError('Файл журнала Windows превышает разрешённый размер.')

    def verify(self):
        if self.api.inspect(self.path, directory=True).identity != self.identity:
            raise ValidationError('Каталог журнала Windows заменён.')
        self.check_files()
        if self.api.inspect(self.path / 'journal.sqlite').identity != self.db_identity:
            raise ValidationError('Файл журнала Windows заменён.')

    def sync(self):
        # Windows does not provide POSIX directory fsync. SQLite's FULL/PERSIST VFS
        # commits flush journal/database; this additionally flushes the held database.
        os.fsync(self.db_fd)

    def snapshot(self, name):
        """Bounded bytes under the process lock; never open SQLite/recover the source."""
        if name not in {'journal.sqlite', 'journal.sqlite-journal'}:
            raise ValidationError('Неизвестный файл снимка журнала.')
        self.verify()
        path = self.path / name
        fd = self.api.open_private(path, create=False, read_only=True)
        try:
            before = os.fstat(fd)
            chunks, remaining = [], self.max_bytes + 1
            while remaining:
                chunk = os.read(fd, min(remaining, 1024 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            if not remaining:
                raise ValidationError('Файл журнала Windows превышает разрешённый размер.')
            after = os.fstat(fd)
            fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            if any(getattr(before, key) != getattr(after, key) for key in fields):
                raise ValidationError('Файл журнала изменился во время чтения.')
            self.verify()
            return b''.join(chunks)
        finally:
            os.close(fd)
