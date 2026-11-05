"""One fixed valid tiny PDF. No caller-supplied paths, content, images or filenames."""

import hashlib
import secrets

from sarex_loader.api_models import ApiError, ApiErrorCode
from sarex_loader.single_test_identity import independent_filename, validate_operation_id
from sarex_loader.single_test_scope import TEST_FILENAME


def synthetic_pdf_bytes(operation_id=None):
    validate_operation_id(operation_id)
    text = b'BT /F1 12 Tf 40 780 Td (Synthetic Sarex Loader test - no customer data.) Tj ET\n'
    if operation_id is not None:
        text += (f'BT /F1 10 Tf 40 750 Td (Independent operation {operation_id}) Tj ET\n').encode()
    objects = [b'<< /Type /Catalog /Pages 2 0 R >>',
               b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
               b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] '
               b'/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
               b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
               f'<< /Length {len(text)} >>\nstream\n'.encode() + text + b'endstream']
    data = bytearray(b'%PDF-1.4\n')
    offsets = [0]
    for identifier, obj in enumerate(objects, 1):
        offsets.append(len(data))
        data.extend(f'{identifier} 0 obj\n'.encode() + obj + b'\nendobj\n')
    xref = len(data)
    data.extend(f'xref\n0 {len(offsets)}\n0000000000 65535 f \n'.encode())
    for offset in offsets[1:]:
        data.extend(f'{offset:010} 00000 n \n'.encode())
    data.extend((f'trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n'
                 f'startxref\n{xref}\n%%EOF\n').encode())
    return bytes(data)


class SyntheticPDF:
    def __init__(self, operation_id=None):
        boundary = 'sarex-single-' + secrets.token_hex(16)
        pdf = synthetic_pdf_bytes(operation_id)
        self.filename = (TEST_FILENAME if operation_id is None
                         else independent_filename(operation_id))
        self.sha256 = hashlib.sha256(pdf).hexdigest()
        self.content_type = 'multipart/form-data; boundary=' + boundary
        self._parts = (
            (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
             f'filename="{self.filename}"\r\nContent-Type: application/pdf\r\n\r\n').encode(),
            pdf, f'\r\n--{boundary}--\r\n'.encode())
        self.content_length = sum(map(len, self._parts))
        self.complete = self._started = False

    def iter_chunks(self):
        if self._started:
            raise ApiError(ApiErrorCode.OUTCOME_UNKNOWN, outcome_unknown=True)
        self._started = True
        yield from self._parts
        self.complete = True

    def close(self):
        self._parts = ()
