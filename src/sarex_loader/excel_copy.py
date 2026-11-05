"""Patch only empty URL cells in a bounded XLSX snapshot, retaining other ZIP members.

No workbook reserialization: tables, styles, formula caches and extension markup stay
unchanged. Publication over the input requires the backup/atomic excel_commit boundary.
"""

import hashlib
import io
import posixpath
import re
from dataclasses import dataclass
from xml.parsers import expat
from xml.sax.saxutils import escape, quoteattr
from zipfile import ZipFile

from openpyxl.utils.cell import coordinate_to_tuple, get_column_letter

from sarex_loader.audit import HEADERS
from sarex_loader.excel_io import (
    MAX_EXPANDED,
    MAX_MEMBER,
    NS,
    REL,
    open_readonly,
    preflight,
    safe_xml,
)
from sarex_loader.safety import ValidationError


@dataclass(frozen=True, repr=False)
class URLUpdate:
    sheet: str
    row: int
    row_id: str
    number: str
    url: str


def _tag_end(data, start):
    quote = None
    for i in range(start, len(data)):
        char = data[i]
        if quote is not None:
            if char == quote:
                quote = None
        elif char in (34, 39):
            quote = char
        elif char == 62:
            return i + 1
    raise ValidationError('Некорректная разметка листа.')


def _patch_sheet(data: bytes, changes: dict[str, str]) -> bytes:
    try:
        data.decode('utf-8')
    except UnicodeError:
        raise ValidationError('Кодировка листа не поддерживается для безопасной копии.') from None
    if b'\x00' in data or re.search(br'encoding\s*=\s*["\'](?!UTF-8|utf-8)', data[:150]):
        raise ValidationError('Кодировка листа не поддерживается для безопасной копии.')
    parser = expat.ParserCreate(namespace_separator='}')
    remaining = dict(changes)
    by_row = {coordinate_to_tuple(ref)[0]: ref for ref in changes}
    patches = []
    active = None
    row_ref = None
    inserted = False

    def new_cell(ref, attrs):
        if attrs.keys() - {'r', 's', 't', 'cm', 'vm', 'ph'}:
            raise ValidationError('Атрибуты URL-ячейки не поддерживаются для копии.')
        attributes = {**attrs, 'r': ref, 't': 'inlineStr'}
        tag = ' '.join(k + '=' + quoteattr(v) for k, v in attributes.items())
        return (f'<c xmlns="{NS}" {tag}><is><t>{escape(changes[ref])}</t></is></c>').encode()

    def start(name, attrs):
        nonlocal active, row_ref, inserted
        if name == NS + '}row':
            row_ref = by_row.get(int(attrs['r']))
            inserted = False
        elif name == NS + '}c' and row_ref is not None:
            ref = attrs['r']
            position = parser.CurrentByteIndex
            if ref == row_ref:
                end = _tag_end(data, position)
                active = (ref, position, end, data[position:end].endswith(b'/>'), attrs)
            elif (row_ref in remaining and not inserted
                  and coordinate_to_tuple(ref)[1] > coordinate_to_tuple(row_ref)[1]):
                patches.append((position, position, new_cell(row_ref, {})))
                inserted = True

    def end(name):
        nonlocal active, row_ref
        if name == NS + '}c' and active is not None:
            ref, begin, tag_end, empty, attrs = active
            finish = tag_end if empty else _tag_end(data, parser.CurrentByteIndex)
            patches.append((begin, finish, new_cell(ref, attrs)))
            remaining.pop(ref)
            active = None
        elif name == NS + '}row' and row_ref is not None:
            if row_ref in remaining:
                if not inserted:
                    position = parser.CurrentByteIndex
                    patches.append((position, position, new_cell(row_ref, {})))
                remaining.pop(row_ref)
            row_ref = None

    parser.StartElementHandler, parser.EndElementHandler = start, end
    parser.Parse(data, True)  # Exact bytes have already passed preflight's DTD/entity rejection.
    if remaining:
        raise ValidationError('Не найдена строка для URL.')
    pieces, previous = [], 0
    for begin, end, value in sorted(patches):
        if begin < previous:
            raise ValidationError('Пересечение изменений URL.')
        pieces.extend((data[previous:begin], value))
        previous = end
    pieces.append(data[previous:])
    result = b''.join(pieces)
    if len(result) > MAX_MEMBER:
        raise ValidationError('Копия листа превышает лимит.')
    return result


def make_url_copy(data: bytes, expected_sha256: str, updates: list[URLUpdate], *,
                  approved_document_ids: tuple[int, ...] | None = None) -> bytes:
    """Validate exact row identity/number and never replace a value, formula or hyperlink."""
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValidationError('INPUT_CHANGED: Excel не совпадает с аудитом.')
    # Opt-in for reviewed local recovery only; mock upload retains its isolated origin.
    if approved_document_ids is not None:
        from sarex_loader.api_models import valid_id

        if (type(approved_document_ids) is not tuple
                or len(approved_document_ids) != len(updates)
                or any(not valid_id(i) for i in approved_document_ids)
                or len(set(approved_document_ids)) != len(approved_document_ids)
                or any(type(u) is not URLUpdate
                       or u.url != f'https://lk.sarex.io/documentations/{i}'
                       for u, i in zip(updates, approved_document_ids, strict=True))):
            raise ValidationError('Нужны явно проверенные назначения ID для локальной копии.')
    metadata = {s['name']: s for s in preflight(data)}
    by_sheet = {}
    for update in updates:
        if (type(update) is not URLUpdate or type(update.row) is not int or update.row < 2
                or update.sheet not in metadata or not isinstance(update.url, str)
                or approved_document_ids is None and not re.fullmatch(
                    r'https://upload\.example\.invalid/documentations/[1-9][0-9]{0,18}',
                    update.url)):
            raise ValidationError('Нужны проверенные строки и синтетические URL.')
        rows = by_sheet.setdefault(update.sheet, {})
        if update.row in rows:
            raise ValidationError('Повтор назначения URL для одной строки.')
        rows[update.row] = update
    changes = {}
    workbook = open_readonly(data)
    try:
        for sheet_name, rows in by_sheet.items():
            sheet = workbook[sheet_name]
            meta = metadata[sheet_name]
            iterator = sheet.iter_rows(max_row=meta['max_row'], max_col=meta['max_column'])
            headers = [c.value for c in next(iterator)]
            if any(headers.count(h) != 1 for h in HEADERS):
                raise ValidationError('Неверные заголовки для записи URL.')
            columns = {h: headers.index(h) for h in HEADERS}
            found = {}
            for number, cells in enumerate(iterator, 2):
                if number not in rows:
                    continue
                update = rows[number]
                cell = cells[columns['URL']]
                ref = f"{get_column_letter(columns['URL'] + 1)}{number}"
                if (str(cells[columns['ID']].value) != update.row_id
                        or cells[columns['Номер']].value != update.number
                        or cell.value not in (None, '') or cell.data_type in {'f', 'e'}
                        or ref in meta['hyperlinks'] or meta['merged']):
                    raise ValidationError('Строка изменена, URL заполнен или неоднозначен.')
                found[ref] = update.url
            if len(found) != len(rows):
                raise ValidationError('Не все строки найдены для записи URL.')
            changes[sheet_name] = found
    finally:
        workbook.close()
    with ZipFile(io.BytesIO(data)) as source:
        if any(i.filename.startswith('_xmlsignatures/') for i in source.infolist()):
            raise ValidationError('Подписанные книги нельзя изменять этим способом.')
        wb = safe_xml(source.read('xl/workbook.xml'))
        relationships = {e.get('Id'): e for e in
                         safe_xml(source.read('xl/_rels/workbook.xml.rels'))}
        parts = {}
        for sheet in wb.findall(f'{{{NS}}}sheets/{{{NS}}}sheet'):
            if sheet.get('name') in changes:
                target = relationships[sheet.get(f'{{{REL}}}id')].get('Target')
                parts[posixpath.normpath(posixpath.join('xl', target)).lstrip('/')] = (
                    changes[sheet.get('name')])
        buffer = io.BytesIO()
        with ZipFile(buffer, 'w') as destination:
            destination.comment = source.comment
            total = 0
            for info in source.infolist():
                raw = source.read(info)
                if info.filename in parts:
                    raw = _patch_sheet(raw, parts[info.filename])
                total += len(raw)
                if total > MAX_EXPANDED:
                    raise ValidationError('Копия Excel превышает лимит распаковки.')
                destination.writestr(info, raw)
        result = buffer.getvalue()
    preflight(result)
    return result
