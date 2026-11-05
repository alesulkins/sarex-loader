"""Only proven Excel misses may move; native no-replace rename, never copy/delete."""

import ctypes
import json
import os
import stat
import sys
from pathlib import Path

from sarex_loader.file_safety import directory_fd
from sarex_loader.folder_resolver import safe_component
from sarex_loader.monthly_folders import filename_date_check
from sarex_loader.pdf_scan import identity
from sarex_loader.reports import _write_bundle
from sarex_loader.safety import ValidationError

DESTINATION = 'не найдено'


def move_plan(files):
    result = []
    for file in files:
        # NOT_FOUND is produced only after a valid, unblocked registry lookup.
        # Punctuation/copy suffixes are not reliable numbers without exact evidence.
        number = file.get('number')
        if (file.get('category') != 'NOT_FOUND' or file.get('excel_candidates')
                or file.get('candidate_group') is not None or file.get('duplicate_groups')
                or not file.get('identity') or not isinstance(number, str)
                or not number.isascii() or not number.isdecimal()
                or filename_date_check(file['filename'], None)):
            continue
        source = Path(file['local_path'])
        result.append({'source': str(source), 'destination': str(source.parent / DESTINATION
                                                               / source.name),
                       'filename': source.name, 'number': number, 'identity': file['identity'],
                       'reason': 'Инспекция не найдена в Excel: ' + source.name})
    return result


def _posix_rename(parent, child, name):
    """Both names are relative to pinned directories; replacement is forbidden in kernel."""
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == 'darwin':
        operation, flag = library.renameatx_np, 4  # RENAME_EXCL
    elif sys.platform.startswith('linux') and hasattr(library, 'renameat2'):
        operation, flag = library.renameat2, 1  # RENAME_NOREPLACE
    else:
        raise ValidationError('Безопасное перемещение без перезаписи недоступно на этой ОС.')
    operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
                          ctypes.c_uint]
    operation.restype = ctypes.c_int
    encoded = os.fsencode(name)
    if operation(parent, encoded, child, encoded, flag):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def move_one(plan):
    source, target = Path(plan['source']), Path(plan['destination'])
    if (not safe_component(source.name) or target != source.parent / DESTINATION / source.name
            or not source.name.lower().endswith('.pdf')):
        raise ValidationError('Небезопасный план перемещения PDF.')
    if os.name == 'nt':
        return _windows_move(source, target, plan['identity'])
    with directory_fd(source.parent) as parent:
        before = os.stat(source.name, dir_fd=parent, follow_symlinks=False)
        if list(identity(before)) != plan['identity'] or not stat.S_ISREG(before.st_mode):
            raise ValidationError('PDF изменился после проверки; перемещение отменено.')
        try:
            os.mkdir(DESTINATION, 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        child = os.open(DESTINATION, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            if list(identity(os.stat(source.name, dir_fd=parent, follow_symlinks=False))) != (
                    plan['identity']):
                raise ValidationError('PDF изменился; перемещение отменено.')
            _posix_rename(parent, child, source.name)
            after = os.stat(source.name, dir_fd=child, follow_symlinks=False)
            if identity(before)[:4] != identity(after)[:4]:
                raise ValidationError('Результат перемещения требует ручной проверки; '
                                      'повтор запрещён.')
            os.fsync(child)
            os.fsync(parent)
        finally:
            os.close(child)


def _windows_move(source, target, expected):
    from ctypes import wintypes

    from sarex_loader.windows_files import _kernel, locked_directory, unavailable, unsafe_link

    with locked_directory(source.parent):
        try:
            target.parent.mkdir()
        except FileExistsError:
            pass
        with locked_directory(target.parent):
            api = _kernel()
            # DELETE + READ_ATTRIBUTES. Deny concurrent writers/renamers; do not read PDF bytes.
            handle = api.CreateFileW(str(source), 0x10080, 1, None, 3, 0x200000, None)
            if handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                before = source.lstat()
                if (list(identity(before)) != expected or not stat.S_ISREG(before.st_mode)
                        or unsafe_link(before) or unavailable(before)):
                    raise ValidationError('PDF изменился или недоступен локально.')

                class RenameInfo(ctypes.Structure):
                    _fields_ = [('replace', wintypes.BOOLEAN), ('root', wintypes.HANDLE),
                                ('length', wintypes.DWORD), ('name', wintypes.WCHAR * 1)]

                encoded = str(target).encode('utf-16-le')
                buffer = ctypes.create_string_buffer(RenameInfo.name.offset + len(encoded) + 2)
                info = RenameInfo.from_buffer(buffer)
                info.replace, info.root, info.length = False, None, len(encoded)
                ctypes.memmove(ctypes.addressof(buffer) + RenameInfo.name.offset, encoded,
                               len(encoded))
                api.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                           wintypes.LPVOID, wintypes.DWORD]
                api.SetFileInformationByHandle.restype = wintypes.BOOL
                if not api.SetFileInformationByHandle(handle, 3, buffer, len(buffer)):
                    raise ctypes.WinError(ctypes.get_last_error())
                if identity(before)[:4] != identity(target.lstat())[:4]:
                    raise ValidationError('Результат перемещения требует ручной проверки.')
            finally:
                api.CloseHandle(handle)


def execute_moves(plans, output, *, protected=()):
    """Durable intent precedes each rename. No retry, overwrite or automatic rollback."""
    if not plans:
        return []
    # The bundle is immutable, so an interrupted run still retains every intended source/target.
    _write_bundle(output, {'move-plan.json': json.dumps(plans, ensure_ascii=False,
                                                      indent=2).encode()}, list(protected))
    results = []
    for number, plan in enumerate(plans, 1):
        status, reason = 'MOVED', plan['reason']
        try:
            move_one(plan)
        except FileExistsError:
            status, reason = 'MOVE_SKIPPED', 'Файл назначения уже существует; перезапись запрещена.'
        except (OSError, ValidationError):
            status, reason = 'MOVE_FAILED', (
                'Перемещение не подтверждено. Проверьте оба пути; автоматического повтора нет.')
        record = {**plan, 'status': status, 'description': reason}
        results.append(record)
        # A separate immutable result bundle per operation survives the next file's failure.
        _write_bundle(output / f'result-{number:05d}', {
            'move.json': json.dumps(record, ensure_ascii=False, indent=2).encode()},
                      list(protected))
        print(reason)
        print('Исходный путь: ' + plan['source'])
        print('Новый путь: ' + plan['destination'])
    return results
