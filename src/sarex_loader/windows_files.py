"""Native Windows customer read/report primitives; no WSL and no reparse traversal.

Handles deny rename/delete while held. Parent handles stay open for the whole
operation. Cloud placeholders are rejected, never hydrated by a metadata scan.
"""

import ctypes
import os
import stat
from contextlib import contextmanager
from ctypes import wintypes

from sarex_loader.safety import ValidationError

REPARSE = 0x400
OFFLINE = 0x1000
RECALL = 0x40000 | 0x400000


def unavailable(info):
    return bool(getattr(info, 'st_file_attributes', 0) & (OFFLINE | RECALL))


def unsafe_link(info):
    # Cloud tags are not name-surrogates; downloaded OneDrive files remain readable.
    # Symlinks/mount points and unknown reparse mechanisms are rejected.
    attrs = getattr(info, 'st_file_attributes', 0)
    tag = getattr(info, 'st_reparse_tag', 0)
    cloud = tag & 0xFFFF0FFF == 0x9000001A
    return bool(attrs & REPARSE and not cloud)


def _kernel():
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                               wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    api.CreateFileW.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    api.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    api.GetDriveTypeW.restype = wintypes.UINT
    return api


def _handle(path, *, directory=False, create=False):
    import msvcrt

    api = _kernel()
    # READ_ATTRIBUTES for directory; files get read or write access. No FILE_SHARE_DELETE.
    access = 0x80 if directory else (0x40000000 if create else 0x80000000)
    share = 3 if directory else 1
    flags = 0x00200000 | (0x02000000 if directory else 0)
    handle = api.CreateFileW(str(path), access, share, None, 1 if create else 3, flags, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        info = path.lstat()
        if unsafe_link(info) or unavailable(info):
            raise ValidationError('Небезопасная ссылка или файл OneDrive не скачан локально.')
        if directory:
            if not stat.S_ISDIR(info.st_mode):
                raise ValidationError('Ожидается локальная папка.')
            return handle
        if not stat.S_ISREG(info.st_mode):
            raise ValidationError('Ожидается обычный локальный файл.')
        return msvcrt.open_osfhandle(handle, (os.O_WRONLY if create else os.O_RDONLY)
                                     | os.O_BINARY | os.O_NOINHERIT)
    except BaseException:
        api.CloseHandle(handle)
        raise


@contextmanager
def locked_directory(path):
    from sarex_loader.config import local_path

    path = local_path(path).absolute()
    handles = []
    api = _kernel()
    try:
        if api.GetDriveTypeW(path.anchor) not in (2, 3):
            raise ValidationError('Нужен локальный диск; сетевые диски не поддерживаются.')
        for component in (*reversed(path.parents), path):
            handles.append(_handle(component, directory=True))
        yield path
    finally:
        for handle in reversed(handles):
            api.CloseHandle(handle)


def read_snapshot(path, limit):
    from sarex_loader.file_safety import _file_identity

    with locked_directory(path.parent):
        fd = _handle(path)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if before.st_size > limit:
                raise ValidationError('Входной файл превышает лимит.')
            data = stream.read(limit + 1)
            if (len(data) > limit or _file_identity(before)
                    != _file_identity(os.fstat(stream.fileno()))):
                raise ValidationError('Файл изменился при чтении или превышает лимит.')
            return data


def scan_metadata(root, max_entries, max_pdf_bytes):
    from sarex_loader.folder_resolver import safe_component
    from sarex_loader.pdf_scan import identity

    with locked_directory(root):
        before_directory = identity(root.stat())
        with os.scandir(root) as entries:
            for count, entry in enumerate(entries, 1):
                if count > max_entries:
                    raise ValidationError('Превышен лимит файлов; отчёт неполон.')
                result = {'filename': entry.name, 'sha256': None, 'size': None,
                          'identity': None, 'reason': None}
                try:
                    # DirEntry.stat on Windows reports st_ino/st_dev as zero.
                    # Fresh lstat-equivalent metadata is required for hard-link detection.
                    info = os.stat(entry.path, follow_symlinks=False)
                    if not safe_component(entry.name) or not entry.name.lower().endswith('.pdf'):
                        result['reason'] = 'UNSAFE_OR_NON_PDF_NAME'
                    elif unsafe_link(info) or not stat.S_ISREG(info.st_mode):
                        result['reason'] = 'SYMLINK_OR_SPECIAL_OR_DIRECTORY'
                    elif unavailable(info):
                        result['reason'] = 'CLOUD_PLACEHOLDER'
                    elif not 0 < info.st_size <= max_pdf_bytes:
                        result['reason'] = 'EMPTY_OR_OVERSIZED_PDF'
                    elif not info.st_ino:
                        result['reason'] = 'PDF_FILE_ID_UNAVAILABLE'
                    else:
                        result.update(size=info.st_size, identity=list(identity(info)))
                except OSError:
                    result['reason'] = 'PDF_UNREADABLE_OR_CHANGED'
                yield result
        if identity(root.stat()) != before_directory:
            raise ValidationError('Каталог PDF изменился во время обхода.')


def write_bundle(output, payloads):
    with locked_directory(output.parent):
        os.mkdir(output, mode=0o700)  # exclusive; COMPLETE remains the last file
        with locked_directory(output):
            for name, data in payloads.items():
                if name != os.path.basename(name) or name in ('.', '..'):
                    raise ValidationError('Небезопасное имя файла результата.')
                fd = _handle(output / name, create=True)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
