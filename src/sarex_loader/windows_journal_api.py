"""Small native Win32 boundary for the private SQLite upload ledger.

No shells, ACL rewrites of existing files, remote paths, or network operations.
Directory security is set atomically at creation; existing ACLs are validated.
"""

import ctypes as c
import os
from contextlib import contextmanager
from dataclasses import dataclass

from sarex_loader.safety import ValidationError

DWORD = c.c_uint32
WORD = c.c_uint16
PTR = c.c_void_p
BOOL = c.c_int32
REPARSE_OR_CLOUD = 0x400 | 0x1000 | 0x40000 | 0x400000


class SecurityAttributes(c.Structure):
    _fields_ = [('length', DWORD), ('descriptor', PTR), ('inherit', BOOL)]


class FileInformation(c.Structure):
    _fields_ = [('attributes', DWORD), ('created', DWORD * 2), ('accessed', DWORD * 2),
                ('written', DWORD * 2), ('volume', DWORD), ('size_high', DWORD),
                ('size_low', DWORD), ('links', DWORD), ('index_high', DWORD),
                ('index_low', DWORD)]


class Acl(c.Structure):
    _fields_ = [('revision', c.c_ubyte), ('reserved', c.c_ubyte), ('size', WORD),
                ('count', WORD), ('reserved2', WORD)]


@dataclass(frozen=True)
class FileInfo:
    identity: tuple[int, int]
    size: int
    links: int
    attributes: int


def validate_acl(owner, aces, current_user, *, token_owner=None):
    """Only this user, SYSTEM and local administrators may be granted any access."""
    allowed = {current_user, 'S-1-5-18', 'S-1-5-32-544'}
    # SQLite creates its own sidecar files. Under an elevated Windows token their
    # owner can be TokenOwner (Administrators), not TokenUser. Do not allow an
    # arbitrary group: only the actual token owner, already in our trusted ACL set.
    owners = {current_user}
    if token_owner in allowed:
        owners.add(token_owner)
    if owner not in owners or not aces:
        raise ValidationError('Журнал должен принадлежать текущему пользователю '
                              'и иметь закрытый ACL.')
    for kind, sid in aces:
        if kind not in (0, 1) or kind == 0 and sid not in allowed:
            raise ValidationError('Права журнала разрешают посторонний или неизвестный доступ.')
    if (0, current_user) not in aces:
        raise ValidationError('Нет явно разрешённого доступа владельца к журналу.')


class WindowsJournalAPI:
    def __init__(self):
        if os.name != 'nt':
            raise ValidationError('Этот файловый адаптер требует настоящую Windows.')
        self.kernel = c.WinDLL('kernel32', use_last_error=True)
        self.security = c.WinDLL('advapi32', use_last_error=True)
        signatures = [
            (self.kernel, 'GetCurrentProcess', [], PTR),
            (self.kernel, 'CloseHandle', [PTR], BOOL),
            (self.kernel, 'LocalFree', [PTR], PTR),
            (self.kernel, 'GetDriveTypeW', [c.c_wchar_p], DWORD),
            (self.kernel, 'CreateDirectoryW', [c.c_wchar_p, c.POINTER(SecurityAttributes)], BOOL),
            (self.kernel, 'CreateFileW', [c.c_wchar_p, DWORD, DWORD, PTR, DWORD, DWORD, PTR], PTR),
            (self.kernel, 'GetFileInformationByHandle', [PTR, c.POINTER(FileInformation)], BOOL),
            (self.security, 'OpenProcessToken', [PTR, DWORD, c.POINTER(PTR)], BOOL),
            (self.security, 'GetTokenInformation',
             [PTR, DWORD, PTR, DWORD, c.POINTER(DWORD)], BOOL),
            (self.security, 'ConvertSidToStringSidW', [PTR, c.POINTER(PTR)], BOOL),
            (self.security, 'ConvertStringSecurityDescriptorToSecurityDescriptorW',
             [c.c_wchar_p, DWORD, c.POINTER(PTR), c.POINTER(DWORD)], BOOL),
            (self.security, 'GetSecurityInfo', [PTR, DWORD, DWORD, c.POINTER(PTR), PTR,
                                              c.POINTER(PTR), PTR, c.POINTER(PTR)], DWORD),
            (self.security, 'GetAce', [PTR, DWORD, c.POINTER(PTR)], BOOL),
        ]
        for library, name, args, result in signatures:
            function = getattr(library, name)
            function.argtypes, function.restype = args, result
        self.user = self._current_user()
        self.owner = self._token_sid(4)  # TokenOwner, used by SQLite-created files.

    def _sid(self, pointer):
        text = PTR()
        if not self.security.ConvertSidToStringSidW(pointer, c.byref(text)):
            raise c.WinError(c.get_last_error())
        try:
            return c.wstring_at(text)
        finally:
            self.kernel.LocalFree(text)

    def _current_user(self):
        return self._token_sid(1)  # TokenUser

    def _token_sid(self, information_class):
        token = PTR()
        if not self.security.OpenProcessToken(self.kernel.GetCurrentProcess(), 8, c.byref(token)):
            raise c.WinError(c.get_last_error())
        try:
            size = DWORD()
            self.security.GetTokenInformation(token, information_class, None, 0, c.byref(size))
            if not 0 < size.value <= 65536:
                raise ValidationError('Не удалось проверить владельца журнала Windows.')
            buffer = c.create_string_buffer(size.value)
            if not self.security.GetTokenInformation(
                    token, information_class, buffer, size, c.byref(size)):
                raise c.WinError(c.get_last_error())
            return self._sid(c.cast(buffer, c.POINTER(PTR))[0])
        finally:
            self.close(token)

    @contextmanager
    def _attributes(self):
        descriptor = PTR()
        # A protected, inheritable ACL is in place before the directory becomes visible.
        sddl = (f'O:{self.user}D:P(A;OICI;FA;;;{self.user})'
                '(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
        if not self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, c.byref(descriptor), None):
            raise c.WinError(c.get_last_error())
        try:
            yield SecurityAttributes(c.sizeof(SecurityAttributes), descriptor, False)
        finally:
            self.kernel.LocalFree(descriptor)

    def create_directory(self, path):
        with self._attributes() as attributes:
            if not self.kernel.CreateDirectoryW(str(path), c.byref(attributes)):
                error = c.get_last_error()
                if error != 183:  # ERROR_ALREADY_EXISTS; existing ACLs are never changed.
                    raise c.WinError(error)

    def close(self, handle):
        self.kernel.CloseHandle(handle)

    def _open(self, path, *, directory=False, data=False, write=False, create=False,
              exclusive=False):
        # Share read/write with SQLite, but NEVER share deletion/rename of held objects.
        access = (0xC0000000 if write else
                  0x80000000 if data else 0x20080)  # READ_CONTROL | FILE_READ_ATTRIBUTES
        if directory:
            access |= 1  # FILE_LIST_DIRECTORY: enforce the no-delete sharing contract.
        flags = 0x00200000 | (0x02000000 if directory else 0x80)
        with self._attributes() as attributes:
            handle = self.kernel.CreateFileW(str(path), access, 0 if exclusive else 3,
                                            c.byref(attributes) if create else None,
                                            4 if create else 3, flags, None)
        if handle == c.c_void_p(-1).value:
            raise c.WinError(c.get_last_error())
        try:
            info = self.info(handle)
            if (bool(info.attributes & 0x10) != directory
                    or info.attributes & REPARSE_OR_CLOUD
                    or not directory and info.links != 1):
                raise ValidationError('Небезопасная ссылка, облачный или специальный файл журнала.')
            return handle
        except BaseException:
            self.close(handle)
            raise

    def directory(self, path):
        if self.kernel.GetDriveTypeW(path.anchor) != 3:
            raise ValidationError('Журнал Windows требует локальный несетевой диск.')
        return self._open(path, directory=True)

    def info(self, handle):
        value = FileInformation()
        if not self.kernel.GetFileInformationByHandle(handle, c.byref(value)):
            raise c.WinError(c.get_last_error())
        return FileInfo((value.volume, value.index_high << 32 | value.index_low),
                        value.size_high << 32 | value.size_low, value.links, value.attributes)

    def private(self, handle):
        owner, acl, descriptor = PTR(), PTR(), PTR()
        result = self.security.GetSecurityInfo(handle, 1, 5, c.byref(owner), None,
                                               c.byref(acl), None, c.byref(descriptor))
        if result:
            raise c.WinError(result)
        try:
            if not owner.value or not acl.value:
                raise ValidationError('У журнала нет ограничивающего доступа ACL.')
            count = c.cast(acl, c.POINTER(Acl)).contents.count
            if not 1 <= count <= 100:
                raise ValidationError('Неизвестные права доступа журнала.')
            aces = []
            for index in range(count):
                ace = PTR()
                if not self.security.GetAce(acl, index, c.byref(ace)):
                    raise c.WinError(c.get_last_error())
                kind = c.c_ubyte.from_address(ace.value).value
                size = WORD.from_address(ace.value + 2).value
                if kind not in (0, 1) or size < 16:
                    raise ValidationError('Неизвестное правило ACL журнала.')
                aces.append((kind, self._sid(ace.value + 8)))
            validate_acl(self._sid(owner), aces, self.user, token_owner=self.owner)
        finally:
            self.kernel.LocalFree(descriptor)

    def inspect(self, path, *, directory=False):
        handle = self._open(path, directory=directory)
        try:
            self.private(handle)
            return self.info(handle)
        finally:
            self.close(handle)

    def open_private(self, path, *, exclusive=False, create=True, read_only=False):
        import msvcrt

        handle = self._open(path, data=True, write=not read_only, create=create,
                            exclusive=exclusive)
        try:
            self.private(handle)
            flags = os.O_RDONLY if read_only else os.O_RDWR
            return msvcrt.open_osfhandle(handle, flags | os.O_BINARY | os.O_NOINHERIT)
        except BaseException:
            self.close(handle)
            raise
