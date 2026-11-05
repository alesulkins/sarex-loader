"""One flat directory pass; bounded streaming fingerprints, no PDF interpretation."""

import hashlib
import os
import stat
import sys
from pathlib import Path

from sarex_loader.file_safety import directory_fd
from sarex_loader.folder_resolver import safe_component
from sarex_loader.safety import ValidationError

CHUNK_BYTES = 1024 * 1024
MAX_ENTRIES = 100_000
MAX_PDF_BYTES = 256 * 1024**2
MAX_TOTAL_BYTES = 8 * 1024**3
# Darwin SDK sys/stat.h defines this bit; Python 3.12 does not expose its name.
CLOUD_PLACEHOLDER_FLAG = getattr(stat, 'SF_DATALESS', 0x40000000 if sys.platform == 'darwin' else 0)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def scan_pdfs(root: Path, *, max_entries=MAX_ENTRIES, max_pdf_bytes=MAX_PDF_BYTES,
              max_total_bytes=MAX_TOTAL_BYTES, metadata_only=False):
    """Yield metadata only. All entries are accounted for, including unsafe/non-PDF files.

    Subdirectories are reported, never traversed (the customer specification is flat).
    Limits stop the entire run: no truncated plan can be published as complete.
    """
    if type(metadata_only) is not bool:
        raise ValidationError('Некорректный режим чтения PDF.')
    for value, ceiling in ((max_entries, MAX_ENTRIES), (max_pdf_bytes, MAX_PDF_BYTES),
                           (max_total_bytes, MAX_TOTAL_BYTES)):
        if type(value) is not int or not 1 <= value <= ceiling:
            raise ValidationError('Некорректный лимит обхода PDF.')
    total = 0
    try:
        if os.name == 'nt':
            if not metadata_only:
                raise ValidationError('На Windows используйте клиентский просмотр без чтения PDF.')
            from sarex_loader.windows_files import scan_metadata

            yield from scan_metadata(root, max_entries, max_pdf_bytes)
            return
        with directory_fd(root) as parent:
            directory_before = identity(os.fstat(parent))
            with os.scandir(parent) as entries:
                for count, entry in enumerate(entries, 1):
                    if count > max_entries:
                        raise ValidationError('Превышен лимит записей каталога PDF; план неполон.')
                    item = {'filename': entry.name, 'sha256': None, 'size': None,
                            'identity': None, 'reason': None}
                    if not safe_component(entry.name) or not entry.name.lower().endswith('.pdf'):
                        item['reason'] = 'UNSAFE_OR_NON_PDF_NAME'
                        yield item
                        continue
                    try:
                        before = entry.stat(follow_symlinks=False)
                        if not stat.S_ISREG(before.st_mode):
                            item['reason'] = 'SYMLINK_OR_SPECIAL_OR_DIRECTORY'
                        elif getattr(before, 'st_flags', 0) & CLOUD_PLACEHOLDER_FLAG:
                            item['reason'] = 'CLOUD_PLACEHOLDER'
                        elif not 0 < before.st_size <= max_pdf_bytes:
                            item['reason'] = 'EMPTY_OR_OVERSIZED_PDF'
                        elif metadata_only:
                            item.update(size=before.st_size, identity=list(identity(before)))
                        else:
                            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                            fd = os.open(entry.name, flags, dir_fd=parent)
                            with os.fdopen(fd, 'rb') as stream:
                                opened = os.fstat(stream.fileno())
                                if identity(opened) != identity(before):
                                    item['reason'] = 'PDF_CHANGED'
                                else:
                                    digest, size, head, tail = hashlib.sha256(), 0, b'', b''
                                    while chunk := stream.read(min(
                                        CHUNK_BYTES, max_pdf_bytes - size + 1,
                                        max_total_bytes - total + 1,
                                    )):
                                        size += len(chunk)
                                        total += len(chunk)
                                        if total > max_total_bytes:
                                            raise ValidationError(
                                                'Превышен общий лимит чтения PDF.')
                                        if not head:
                                            head = chunk[:8]
                                        tail = (tail + chunk)[-1024:]
                                        digest.update(chunk)
                                        if size > max_pdf_bytes:
                                            break
                                    after = os.fstat(stream.fileno())
                                    current = os.stat(entry.name, dir_fd=parent,
                                                      follow_symlinks=False)
                                    if (identity(before) != identity(after)
                                            or identity(after) != identity(current)
                                            or size != before.st_size or size > max_pdf_bytes):
                                        item['reason'] = 'PDF_CHANGED'
                                    elif not head.startswith(b'%PDF-') or b'%%EOF' not in tail:
                                        item['reason'] = 'PDF_SIGNATURE_OR_EOF_MISSING'
                                    else:
                                        item.update(sha256=digest.hexdigest(), size=size,
                                                    identity=list(identity(after)))
                    except OSError:
                        item['reason'] = 'PDF_UNREADABLE_OR_CHANGED'
                    yield item
            if directory_before != identity(os.fstat(parent)):
                raise ValidationError('Каталог PDF изменился при обходе; повторите аудит.')
    except OSError:
        raise ValidationError('Не удалось безопасно обойти локальный каталог PDF.') from None
