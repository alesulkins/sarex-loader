"""Single-use multipart/form-data PDF stream. No network, no source mutations."""

import hashlib
import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import ExitStack
from pathlib import Path

from sarex_loader.api_models import ApiError, ApiErrorCode
from sarex_loader.config import checked_path, local_path, within_root
from sarex_loader.file_safety import directory_fd
from sarex_loader.folder_resolver import safe_component
from sarex_loader.pdf_scan import CLOUD_PLACEHOLDER_FLAG, MAX_PDF_BYTES, identity

CHUNK_SIZE = 65536


class MultipartPDF:
    def __init__(self, input_root: Path, path: Path, *, expected_sha256: str | None = None):
        self._stack = ExitStack()
        self._started = False
        self._closed = False
        self.complete = False
        failed = False
        try:
            root = checked_path(local_path(input_root), directory=True)
            self.path = within_root(path, root, directory=False)
            if not safe_component(self.path.name) or self.path.suffix.lower() != '.pdf':
                raise ApiError(ApiErrorCode.INVALID_SOURCE)
            if os.name == 'nt':
                from sarex_loader.windows_files import _handle, locked_directory

                self._parent = self._stack.enter_context(locked_directory(self.path.parent))
                fd = _handle(self.path)  # Deny writes/delete; reject reparse/cloud placeholders.
            else:
                self._parent = self._stack.enter_context(directory_fd(self.path.parent))
                fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=self._parent)
            self._stream = self._stack.enter_context(os.fdopen(fd, 'rb'))
            info = os.fstat(self._stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_PDF_BYTES
                    or getattr(info, 'st_flags', 0) & CLOUD_PLACEHOLDER_FLAG):
                raise ApiError(ApiErrorCode.INVALID_SOURCE)
            self._identity = identity(info)
            self.filename = self.path.name
            boundary = 'sarex-' + secrets.token_hex(24)
            self.content_type = 'multipart/form-data; boundary=' + boundary
            self._prefix = (
                f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
                f'filename="{self.filename}"\r\nContent-Type: application/pdf\r\n\r\n'
            ).encode()
            self._suffix = f'\r\n--{boundary}--\r\n'.encode('ascii')
            self.content_length = len(self._prefix) + info.st_size + len(self._suffix)
            digest, head, tail, size = hashlib.sha256(), b'', b'', 0
            marker = boundary.encode('ascii')
            while chunk := self._stream.read(CHUNK_SIZE):
                size += len(chunk)
                if size > info.st_size or marker in tail + chunk:
                    raise ApiError(ApiErrorCode.INVALID_SOURCE)
                if not head:
                    head = chunk[:8]
                tail = (tail + chunk)[-1024:]
                digest.update(chunk)
            if size != info.st_size or not head.startswith(b'%PDF-') or b'%%EOF' not in tail:
                raise ApiError(ApiErrorCode.INVALID_SOURCE)
            self.sha256 = digest.hexdigest()
            if expected_sha256 is not None and self.sha256 != expected_sha256:
                raise ApiError(ApiErrorCode.INVALID_SOURCE)
            self._check_identity()
            self._stream.seek(0)
        except Exception:
            self._stack.close()
            failed = True
        except BaseException:
            self._stack.close()
            raise
        if failed:
            raise ApiError(ApiErrorCode.INVALID_SOURCE)

    def _check_identity(self) -> None:
        from sarex_loader.file_safety import child_stat

        if (identity(os.fstat(self._stream.fileno())) != self._identity
                or identity(child_stat(self._parent, self.path.name)) != self._identity):
            raise ApiError(ApiErrorCode.INVALID_SOURCE)

    def iter_chunks(self) -> Iterator[bytes]:
        if self._started or self._closed:
            raise ApiError(ApiErrorCode.OUTCOME_UNKNOWN, outcome_unknown=True)
        self._started = True
        try:
            self._check_identity()
            yield self._prefix
            digest, size = hashlib.sha256(), 0
            while chunk := self._stream.read(CHUNK_SIZE):
                size += len(chunk)
                if size > self._identity[2]:
                    raise ApiError(ApiErrorCode.INVALID_SOURCE)
                digest.update(chunk)
                yield chunk
            self._check_identity()
            if size != self._identity[2] or digest.hexdigest() != self.sha256:
                raise ApiError(ApiErrorCode.INVALID_SOURCE)
            yield self._suffix
            self.complete = True
        finally:
            self.close()

    def close(self) -> None:
        self._closed = True
        self._stack.close()

    def __enter__(self) -> 'MultipartPDF':
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
