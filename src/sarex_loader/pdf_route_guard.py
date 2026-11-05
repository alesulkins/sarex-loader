"""Veto contradictory filename/Excel evidence; never route by a guessed filename.

Customer production roots only. These checks do not replace Excel, resolve aliases,
select another Excel row, or grant permission to upload/create anything.
"""

import re

VERSION = 'filename-context-v1'
ROOTS = {2066367, 2067117}
SCOPES = {'овн', 'опв', 'пад', 'нк', 'вк', 'гтс', 'мост', 'мад',
          'ад', 'екпв', 'хе', 'пн', 'пе', 'пруд', 'накопитель'}


def words(value):
    return re.findall(r'[а-яёa-z0-9]+', str(value or '').casefold())


def families(value):
    tokens = words(value)
    found = set()
    for family, variants in {
        'Хедмайнер': {'хедмайнер'}, 'БиДжи': {'биджи', 'биджии', 'биджиинжиниринг'},
        'РСУ': {'рсу'}, 'ЮСР': {'юср'}, 'Сфера': {'сфера'}, 'НПО Процесс': {'процесс'},
        'СМИ': {'сми', 'союзмаш'}, 'НТГ': {'нтг', 'нерудтрейдгрупп'},
        'ИТЭ': {'итэ', 'интертехэлектро'}, 'Новолекс': {'новолекс'},
        'Энергосервис': {'энергосервис'}, 'ТСМ': {'тсм', 'таймырстроймонтаж'},
        'КРОК': {'крок'}, 'СиТЭК': {'ситэк'},
    }.items():
        if set(tokens) & variants:
            found.add(family)
    joined = ' '.join(tokens)
    if 'неруд трейд групп' in joined:
        found.add('НТГ')
    if 'фнс' in tokens or 'фнсервис' in tokens or 'фн сервис' in joined:
        found.add('ФН Сервис')
    if 'рти строй' in joined:
        found.add('РТИ-Строй')
    elif 'рти' in tokens or 'рт инжиниринг' in joined:
        found.add('РТ-Инжиниринг')
    return found


def filename_route_checks(filename, record, root_id):
    """Return all observed conflicts, independent of successful folder resolution."""
    if str(root_id) not in {str(r) for r in ROOTS}:
        return []
    # Exclude the suffix number (which can itself include an office designation).
    body = filename[:-4].rpartition('-')[0]
    tokens = set(words(body))
    observed, expected = families(body), families(record.get('contractor'))
    checks = []
    evidence = {'filename': filename, 'row': record.get('row'),
                'excel_office': record.get('office'),
                'excel_contractor': record.get('contractor'),
                'filename_contractors': sorted(observed),
                'filename_offices': sorted(tokens & {'оф', 'мг', 'тэц'}),
                'filename_scopes': sorted(tokens & SCOPES)}

    def reject(code):
        checks.append({'code': code, **evidence})

    # These two names share only their explicitly approved OVN/OPV branch;
    # project scopes are independently checked below.
    allowed = expected | ({'Хедмайнер', 'ФН Сервис'}
                          if expected & {'Хедмайнер', 'ФН Сервис'} else set())
    if observed and expected and not observed <= allowed:
        reject('PDF_CONTRACTOR_MISMATCH')
    office = str(record.get('office') or '').casefold()
    if tokens & {'оф', 'мг', 'тэц'} and tokens & {'оф', 'мг', 'тэц'} != {office}:
        reject('PDF_OFFICE_MISMATCH')
    scope = set(words(record.get('contractor'))) & SCOPES
    observed_scope = tokens & SCOPES
    if expected & {'Хедмайнер', 'ФН Сервис'}:
        if ('овн' in scope and observed_scope != {'овн'}
                or 'нк' in scope and observed_scope != {'нк'}
                or not scope & {'овн', 'нк'} and observed_scope & {'овн', 'нк'}):
            reject('PDF_PROJECT_SCOPE_MISMATCH')
        # No GTS/OVN/NK/MOST/MAD fallback into the approved OPV/PAD branch.
        if scope & {'опв', 'пад'} and observed_scope & {'гтс', 'мост', 'мад'}:
            reject('PDF_PROJECT_SCOPE_MISMATCH')
    if office == 'мг' and expected & {'РСУ', 'ЮСР', 'БиДжи'} and 'мг' not in tokens:
        reject('PDF_MG_CONTEXT_UNVERIFIED')
    return list({c['code']: c for c in checks}.values())


def required_parent(root_id, record):
    """Confirmed branch IDs; a month must be within this exact parent."""
    root = str(root_id)
    family = families(record.get('contractor'))
    scope = set(words(record.get('contractor'))) & SCOPES
    if root not in {str(r) for r in ROOTS}:
        return None
    if family & {'Хедмайнер', 'ФН Сервис'} and 'овн' in scope:
        return 4768006 if root == '2066367' else 4767813
    if root == '2066367' and 'Хедмайнер' in family and 'нк' in scope:
        return 7893025
    if root == '2067117' and record.get('office') == 'МГ':
        return {'РСУ': 6108617, 'ЮСР': 6580754, 'БиДжи': 6641753}.get(
            next(iter(family)) if len(family) == 1 else None)
    return None


def destination_check(root_id, record, path_ids):
    expected = required_parent(root_id, record)
    if expected is not None and expected not in path_ids:
        return {'code': 'PDF_DESTINATION_BRANCH_MISMATCH', 'required_parent_id': expected,
                'observed_path_ids': list(path_ids), 'row': record.get('row')}
    return None
