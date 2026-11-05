"""Conservative per-parent calendar naming. Pure planning, no HTTP or mutation."""

import re
from collections import Counter
from datetime import date

from sarex_loader.folder_resolver import MONTHS, calendar_month, collision_key


def month_number(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{4}-(0[1-9]|1[0-2])', value):
        raise ValueError('Некорректный календарный месяц.')
    year, month = map(int, value.split('-'))
    date(year, month, 1)
    return year * 12 + month - 1


def infer_month_name(children, month, *, parent_id=None, parent_path=()):
    """Check the whole observed sibling set; never count created or requested folders.

    Older undecodable labels are disclosed, not used as calendar anchors. A label
    that could denote the requested month or a future number blocks inference.
    Inference is NOT evidence of a complete listing and never authorizes a POST.
    """
    target = month_number(month)
    folders = [d for d in children if d.is_folder]
    known, unknown, numbers = [], [], []
    for item in folders:
        prefix = re.match(r'^([0-9]+)\.', item.name)
        if prefix:
            numbers.append(int(prefix[1]))
        label_name = item.name
        # Explicit customer fact, limited to the known VK / ТЭЦ parent.
        if parent_id == 2067146 and re.fullmatch(r'\d+\.\s*[А-Яа-я]+', label_name):
            label_name += ' 2022'
        parsed = calendar_month(label_name)
        if parsed is None:
            unknown.append(item.name)
            continue
        russian = re.fullmatch(r'(?:(\d+)\.(\s*))?([А-Яа-я]+) (\d{4})', label_name)
        if re.fullmatch(r'\d{4}-\d{2}', item.name):
            style = ('iso', '', '')
        elif russian and russian[3].casefold() in MONTHS:
            case = 'title' if russian[3] == russian[3].capitalize() else 'lower'
            if russian[3] not in (russian[3].capitalize(), russian[3].lower()):
                return {'status': 'MONTH_NAMING_AMBIGUOUS', 'name': None}
            spacing = russian[2] or ''
            # User-confirmed isolated typo at this exact VK parent. Other formats stay strict.
            if parent_id == 2067146 and russian[1] and spacing in ('', ' '):
                spacing = ' '
            style = ('numbered' if russian[1] else 'russian', spacing, case)
        else:
            return {'status': 'MONTH_NAMING_AMBIGUOUS', 'name': None}
        known.append((item, parsed, style, int(prefix[1]) if prefix else None))
    if any(count > 1 for count in Counter(p for _, p, _, _ in known).values()):
        return {'status': 'DUPLICATE_MONTH', 'name': None}
    if any(count > 1 for count in Counter(numbers).values()):
        return {'status': 'DUPLICATE_MONTH_PREFIX', 'name': None}
    existing = [d for d, parsed, _, _ in known if parsed == month]
    if existing:
        return {'status': 'MONTH_ALREADY_EXISTS', 'name': existing[0].name,
                'folder_id': existing[0].id}
    # User-confirmed policy: one unambiguous anchor is sufficient. Calendar distance,
    # duplicate checks and inconsistent multiple-anchor rejection remain unchanged.
    if not known or len({style for _, _, style, _ in known}) != 1:
        return {'status': 'MONTH_NAMING_AMBIGUOUS', 'name': None}
    style = known[0][2]
    latest = max(known, key=lambda k: k[1])
    word = MONTHS[int(month[-2:]) - 1]
    if any(word in name.casefold() or month in name for name in unknown):
        return {'status': 'MONTH_NAMING_AMBIGUOUS', 'name': None,
                'unparsed_names': unknown}
    if style[0] == 'iso':
        name = month
    else:
        label = (word.capitalize() if style[2] == 'title' else word) + ' ' + month[:4]
        if style[0] == 'numbered':
            offsets = {n - month_number(parsed) for _, parsed, _, n in known}
            # Approved exception only in VK / 06-МГ / РСУ.МГ. Never infer this policy
            # from an irregular sequence at an arbitrary parent.
            if parent_id == 6108617 and 2067117 in parent_path:
                anchors = {parsed: n for _, parsed, _, n in known}
                required = {'2026-02': 1, '2026-04': 2, '2026-05': 3}
                anchor_offset = 3 - month_number('2026-05')
                if (any(anchors.get(m) != n for m, n in required.items())
                        or target <= month_number('2026-05')
                        or any(m not in required and (m <= '2026-05'
                               or n - month_number(m) != anchor_offset)
                               for m, n in anchors.items())):
                    return {'status': 'MONTH_EXCEPTION_CONFLICT', 'name': None}
                offsets = {anchor_offset}
            if len(offsets) != 1:
                return {'status': 'MONTH_NUMBERING_INCONSISTENT', 'name': None}
            sequence = target + next(iter(offsets))
            if sequence < 1 or sequence in numbers:
                return {'status': 'DUPLICATE_MONTH_PREFIX', 'name': None}
            if any((m := re.match(r'^(\d+)\.', u)) and int(m[1]) >= latest[3]
                   for u in unknown):
                return {'status': 'MONTH_NAMING_AMBIGUOUS', 'name': None}
            name = f'{sequence}.{style[1]}{label}'
        else:
            name = label
    # A file can also occupy the requested name. Do not silently ignore it.
    if any(collision_key(d.name) == collision_key(name) for d in children):
        return {'status': 'MONTH_NAME_COLLISION', 'name': None}
    return {'status': 'MONTH_NAME_INFERRED', 'name': name, 'format': style[0],
            'last_month_name': latest[0].name, 'last_month_id': latest[0].id,
            'anchors_checked': len(known), 'unparsed_names': unknown}


def filename_date_check(filename, excel_date):
    """Excel stays authoritative. A recognizable invalid/mismatching prefix blocks upload."""
    match = re.match(r'^(\d{4}-\d{2}-\d{2})(?:-|_)', filename)
    if not match:
        if re.match(r'^\d{4}[-_]', filename):
            return {'code': 'PDF_DATE_INVALID', 'pdf_date': filename[:10],
                    'excel_date': excel_date}
        return None
    try:
        pdf_date = date.fromisoformat(match[1])
    except (ValueError, TypeError, AttributeError):
        return {'code': 'PDF_DATE_INVALID', 'pdf_date': match[1], 'excel_date': excel_date}
    if not excel_date:
        return None
    try:
        source_date = date.fromisoformat(excel_date[:10])
    except (ValueError, TypeError):
        return {'code': 'EXCEL_DATE_INVALID', 'pdf_date': match[1], 'excel_date': excel_date}
    if pdf_date != source_date:
        return {'code': 'DATE_MISMATCH', 'pdf_date': match[1],
                'excel_date': excel_date}
    return None
