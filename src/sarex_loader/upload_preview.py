"""All-file, multi-directory upload preview using existing audit, matching and resolver."""

import csv
import hashlib
import io
import json
import os
from collections import Counter, defaultdict
from pathlib import Path

from sarex_loader.audit import audit_registry
from sarex_loader.config import checked_path
from sarex_loader.confirmed_absences import CONFIRMED_MISSING_MONTHS
from sarex_loader.file_safety import read_snapshot
from sarex_loader.folder_resolver import collision_key
from sarex_loader.journal import fingerprint
from sarex_loader.matching import (
    InspectionIndex,
    build_match_report,
    extract_number,
    pdf_dates_may_match,
)
from sarex_loader.messages import describe
from sarex_loader.monthly_folders import filename_date_check, infer_month_name
from sarex_loader.pdf_route_guard import destination_check
from sarex_loader.pdf_scan import MAX_ENTRIES, identity, scan_pdfs
from sarex_loader.preview_messages import explain_file
from sarex_loader.reports import _write_bundle, literal
from sarex_loader.safety import ValidationError
from sarex_loader.tree_acceptance import operational_tree
from sarex_loader.tree_source import (
    read_tree,
    resolve_observed_path,
    snapshot_payloads,
    tree_snapshot,
    tree_summary,
)


def inventory(roots, *, flat=False):
    files, ignored, manifests = [], [], {}
    seen = set()
    for root in roots:
        root = checked_path(Path(root), directory=True)
        for folder, directories, _ in os.walk(root, followlinks=False):
            current = checked_path(Path(folder), directory=True)
            if current in seen:
                raise ValidationError('Каталоги PDF пересекаются; один файл учтён дважды.')
            seen.add(current)
            if flat:
                ignored.extend({'path': str(current / name), 'reason': 'SUBDIRECTORY_NOT_SCANNED'}
                               for name in directories)
                directories.clear()
            if len(seen) > 10000:
                raise ValidationError('Превышен лимит каталогов; частичный отчёт запрещён.')
            for name in list(directories):
                if (current / name).is_symlink():
                    directories.remove(name)
                    ignored.append({'path': str(current / name), 'reason': 'SYMLINK_DIRECTORY'})
            manifests[str(current)] = list(identity(current.stat()))
            for entry in scan_pdfs(current, metadata_only=True):
                entry['local_path'] = str(current / entry['filename'])
                if entry['filename'].lower().endswith('.pdf'):
                    files.append(entry)
                elif (current / entry['filename']).is_file():
                    ignored.append({'path': entry['local_path'], 'reason': entry['reason']})
                if len(files) + len(ignored) > MAX_ENTRIES:
                    raise ValidationError('Превышен лимит файлов; частичный отчёт запрещён.')
    return sorted(files, key=lambda x: x['local_path']), ignored, manifests


def full_path(index, identifier):
    item = index.documents.get(identifier)
    if not item:
        return ''
    context = getattr(index, 'context_names', {})
    return ' → '.join(index.documents[i].name if i in index.documents else context.get(i, f'ID:{i}')
                      for i in item.path_ids)


def route_details(index, root, parts, confirmed_missing):
    resolution = resolve_observed_path(index, root, parts)
    if resolution.folder_id:
        return {'folder_status': resolution.status, 'folder_id': resolution.folder_id,
                'parent_id': None, 'full_path': full_path(index, resolution.folder_id),
                'need_folder': False, 'naming': None}
    result = {'folder_status': resolution.status, 'folder_id': None, 'parent_id': None,
              'full_path': full_path(index, root) + ' → ' + ' → '.join(
                  p[9:-1] if p.startswith('{company:') else
                  p[7:-1] if p.startswith('{month:') else p for p in parts),
              'need_folder': False, 'naming': None}
    if (resolution.status != 'FOLDER_NOT_RESOLVED_IN_SNAPSHOT' or not parts
            or not parts[-1].startswith('{month:') or not parts[-1].endswith('}')):
        return result
    parent = resolve_observed_path(index, root, parts[:-1])
    if parent.folder_id is None:
        for position, part in enumerate(parts[:-1]):
            prefix = resolve_observed_path(index, root, parts[:position + 1])
            if prefix.folder_id is None:
                if prefix.status == 'FOLDER_NOT_RESOLVED_IN_SNAPSHOT' and operational_tree(index):
                    result['missing_component'] = (
                        part[9:-1] if part.startswith('{company:') else part)
                    result['missing_level'] = ('папка подрядчика' if part.startswith('{company:')
                                               else 'папка раздела')
                break
        return result
    month = parts[-1][7:-1]
    naming = infer_month_name(list(index.children[parent.folder_id].values()), month,
                              parent_id=parent.folder_id, parent_path=parent.path_ids)
    manual = (parent.folder_id, month) in confirmed_missing | CONFIRMED_MISSING_MONTHS
    accepted = operational_tree(index)
    absent = manual or accepted
    result.update(parent_id=parent.folder_id, month=month, naming=naming,
                  parent_path=list(parent.path_ids),
                  parent_full_path=full_path(index, parent.folder_id),
                  need_folder=absent, absence_confirmed_manually=manual,
                  folder_status='MONTH_CREATION_REQUIRED' if absent else 'MONTH_ABSENCE_UNVERIFIED',
                  creation_allowed=False, creation_blockers=['FOLDER_CREATION_DISABLED']
                  + ([] if accepted else ['TREE_COMPLETENESS_UNVERIFIED']))
    if naming['name'] and naming['status'] == 'MONTH_NAME_INFERRED':
        result['full_path'] = result['parent_full_path'] + ' → ' + naming['name']
    else:
        result['creation_blockers'].append(naming['status'])
    return result


def run_full_preview(config, pdf_roots, output, *, confirmed_missing=(), flat=False,
                     move_not_found=False, tree_index=None, plan_moves=False):
    if config.tree is None or config.tree.source != 'gateway':
        raise ValidationError('Полный просмотр требует свежий источник Gateway.')
    if set(pdf_roots) != {r.inspection_type for r in config.registries}:
        raise ValidationError('Укажите PDF-каталоги для каждого реестра.')
    registries = [audit_registry(c) for c in config.registries]
    inspections = InspectionIndex(registries, config.routes)
    files, ignored, manifests = [], [], {}
    for kind, roots in pdf_roots.items():
        entries, skipped, folders = inventory(roots, flat=flat)
        ignored.extend(skipped)
        if manifests.keys() & folders.keys():
            raise ValidationError('Папки разных реестров пересекаются.')
        manifests.update(folders)
        matched = build_match_report(inspections, entries, kind, config.separator,
                                     config.numbers.get(kind))
        files.extend(matched['files'])
    if len(files) > MAX_ENTRIES:
        raise ValidationError('Превышен общий лимит PDF.')
    paths = set()
    for file in files:
        group = file['candidate_group']
        members = file.get('selected_candidate_ids',
                           inspections.groups[group]['candidate_ids'] if group is not None else [])
        file['excel_candidates'] = [inspections.candidates[i] for i in members]
        for candidate in file['excel_candidates']:
            proposal = candidate['proposed_folder']
            if proposal:
                paths.add((int(proposal['root_id']), tuple(proposal['components'])))
    index = tree_index if tree_index is not None else read_tree(
        config.tree, paths, allow_browser=True)
    accepted = operational_tree(index)
    resolutions = {(root, parts): route_details(index, root, parts, set(confirmed_missing))
                   for root, parts in paths}
    remote_names, remote_numbers = defaultdict(list), defaultdict(list)
    for d in index.documents.values():
        if not d.is_folder and len(d.path_ids) > 1:
            remote_names[d.path_ids[-2], collision_key(d.name)].append(d.id)
            number = extract_number(d.name, config.separator)
            if number:
                remote_numbers[d.path_ids[-2], collision_key(number)].append(d.id)
    planned_folders = {}
    for file in files:
        candidates = file['excel_candidates']
        candidate = candidates[0] if len(candidates) == 1 else None
        file.update(status=file['category'], status_description=describe(file['category']),
                    folder_id=None, parent_id=None, full_path='', need_folder=False,
                    folder_status=None, ready_to_upload=False, ready_by_metadata=False,
                    remote_document_ids=[], date_conflict=None)
        file['row'] = candidate['row'] if candidate else None
        file['sheet'] = candidate['sheet'] if candidate else None
        file['excel_date'] = candidate['date'] if candidate else None
        # Independent of route availability, local duplicates and candidate validation.
        file['candidate_date_checks'] = [
            {**check, 'row': c['row'], 'sheet': c['sheet'], 'number': c['number']}
            for c in candidates
            if (check := filename_date_check(file['filename'], c['date']))]
        invalid_pdf_date = filename_date_check(file['filename'], None)
        if invalid_pdf_date:
            file['reasons'].append(invalid_pdf_date['code'])
            file['status'] = invalid_pdf_date['code']
        if candidate and file['candidate_date_checks']:
            file['date_conflict'] = file['candidate_date_checks'][0]
        if candidate and candidate['proposed_folder']:
            proposal = candidate['proposed_folder']
            detail = resolutions[int(proposal['root_id']), tuple(proposal['components'])]
            file.update(detail)
            destination = file['folder_id'] or file['parent_id']
            if destination and (check := destination_check(
                    proposal['root_id'], candidate, index.documents[destination].path_ids)):
                file['filename_route_checks'].append(check)
                file['reasons'].append(check['code'])
                file['category'] = 'INVALID_REGISTRY_DATA'
                file['status'] = 'INVALID_REGISTRY_DATA'
            if file['folder_id']:
                file['remote_document_ids'] = sorted(set(
                    remote_names.get((file['folder_id'], collision_key(file['filename'])), [])
                    + [identifier for number in {file['number'],
                                                 file.get('extracted_number') or file['number']}
                       for identifier in remote_numbers.get(
                           (file['folder_id'], collision_key(number)), [])
                       if pdf_dates_may_match(file['filename'], index.documents[identifier].name)]))
        if candidate:
            file['reasons'] = list(dict.fromkeys([*file['reasons'], *candidate['reasons']]))
        if file['category'] == 'MATCHED' and not invalid_pdf_date:
            if file['date_conflict']:
                file['status'] = file['date_conflict']['code']
            elif candidate['existing_url']:
                file['status'] = 'EXISTING_URL'
            elif file['remote_document_ids']:
                file['status'] = 'REMOTE_DOCUMENT_EXISTS'
            elif file['folder_id']:
                file['status'] = 'READY_BY_METADATA' if accepted else 'TREE_COMPLETENESS_UNVERIFIED'
                file['ready_by_metadata'] = True
            else:
                file['status'] = file['folder_status'] or 'ROUTE_NOT_CONFIGURED'
        if file['date_conflict']:
            file['reasons'].append(file['date_conflict']['code'])
            file['date_conflict'].update(filename=file['filename'],
                                         excel_destination=file['full_path'])
        # Keep independent blockers rather than losing them to primary status precedence.
        if candidate and candidate['existing_url']:
            file['reasons'].append('EXISTING_URL')
        if file['remote_document_ids']:
            file['reasons'].append('REMOTE_DOCUMENT_EXISTS')
        if file['folder_status'] and not file['folder_id']:
            file['reasons'].append(file['folder_status'])
        file['reasons'] += [c['code'] for c in file['candidate_date_checks']]
        if not accepted:
            file['reasons'].append('TREE_COMPLETENESS_UNVERIFIED')
        file['reasons'].append('PDF_CONTENT_NOT_VERIFIED')
        if file.get('naming') and file['naming']['status'] != 'MONTH_NAME_INFERRED':
            file['reasons'].append(file['naming']['status'])
        file['reasons'] = list(dict.fromkeys(file['reasons']))
        file['status_description'] = describe(file['status'])
        file['reason_description'] = explain_file(file)
        if file['parent_id']:
            key = file['parent_id'], file['month']
            if key not in planned_folders:
                planned_folders[key] = {k: file.get(k) for k in (
                    'parent_id', 'parent_full_path', 'parent_path', 'month', 'full_path',
                    'naming', 'absence_confirmed_manually', 'creation_allowed',
                    'creation_blockers')}
                planned_folders[key].update(pdf_count=0, waiting_without_conflict=0)
            planned_folders[key]['pdf_count'] += 1
            if file['category'] == 'MATCHED' and not file['date_conflict']:
                planned_folders[key]['waiting_without_conflict'] += 1
    # Recheck metadata and source hashes before publishing a complete report.
    for path, before in manifests.items():
        if list(identity(Path(path).stat())) != before:
            raise ValidationError('Каталог PDF изменился во время проверки.')
    for file in files:
        if (file['identity']
                and list(identity(Path(file['local_path']).lstat())) != file['identity']):
            raise ValidationError('PDF изменился во время проверки; повторите просмотр.')
    for c, r in zip(config.registries, registries, strict=True):
        if hashlib.sha256(read_snapshot(c.excel, c.max_file_bytes)).hexdigest() != r['sha256']:
            raise ValidationError('Excel изменился во время проверки.')
    count = len(files)
    report = {'mode': 'FULL_UPLOAD_PREVIEW', 'dry_run': True, 'write_enabled': False,
              'pdf_contents_read': False, 'journal_updated': False,
              'summary': dict(Counter(f['status'] for f in files)),
              'counts': {'total_pdf': count,
                         'matched_excel': sum(f['category'] == 'MATCHED' for f in files),
                         'ready_to_upload': 0,
                         'ready_by_metadata': sum(f['ready_by_metadata'] for f in files),
                         'already_in_sarex': sum(bool(f['remote_document_ids']) for f in files),
                         'requires_folder': sum(f['need_folder'] for f in files),
                         'missing_month_unconfirmed': sum(f['folder_status']
                             == 'MONTH_ABSENCE_UNVERIFIED' for f in files),
                         'date_conflicts': sum(bool(f['date_conflict']) for f in files),
                         'problem_files': sum(f['category'] != 'MATCHED'
                             or bool(f['date_conflict']) for f in files)},
              'files': files, 'planned_folders': list(planned_folders.values()),
              'ignored_entries': ignored, 'registry_sources': inspections.registry_sources,
              'tree': tree_summary(config.tree, index)}
    report['coverage'] = {
        'matched_excel_percent': round(100 * report['counts']['matched_excel'] / count, 2)
        if count else 0,
        'confirmed_folder_percent': round(100 * sum(bool(f['folder_id']) for f in files)
                                         / count, 2) if count else 0,
        'ready_to_upload_percent': 0,
    }
    report['plan_sha256'] = fingerprint({'files': files, 'tree': report['tree']['sha256'],
                                         'sources': [r['sha256'] for r in registries]})
    if move_not_found or plan_moves:
        from sarex_loader.local_moves import move_plan

        if not flat or len(pdf_roots) != 1 or (
                move_not_found and sum(map(len, pdf_roots.values())) != 1):
            raise ValidationError('Перемещение разрешено только для одного плоского каталога.')
        report['local_move_plan'] = move_plan(files)
        planned_sources = {item['source'] for item in report['local_move_plan']}
        for file in files:
            if file['category'] == 'NOT_FOUND' and file['local_path'] not in planned_sources:
                file['reasons'].append('LOCAL_MOVE_NOT_PROVEN')
                file['reason_description'] += (
                    '; Перемещение не разрешено: номер извлечён ненадёжно или есть другая ошибка')
        report['local_moves_audit_directory'] = str(output.with_name(output.name + '-moves'))
        report['local_moves_enabled'] = move_not_found
        report['plan_sha256'] = fingerprint({
            'files': files, 'tree': report['tree']['sha256'],
            'sources': [r['sha256'] for r in registries],
            'local_move_plan': report['local_move_plan']})
    payloads = preview_payloads(report)
    snapshot = tree_snapshot(config.tree, index)
    if snapshot:
        payloads.update(snapshot_payloads(snapshot, config.tree.max_response_bytes))
    _write_bundle(output, payloads, [*(c.excel.parent for c in config.registries),
                                    *(p for roots in pdf_roots.values() for p in roots)])
    if move_not_found:
        from sarex_loader.local_moves import execute_moves

        report['local_moves'] = execute_moves(
            report['local_move_plan'], Path(report['local_moves_audit_directory']),
            protected=[*(c.excel.parent for c in config.registries),
                       *(p for roots in pdf_roots.values() for p in roots)])
    return report


def preview_payloads(report):
    headers = ['Локальный PDF', 'Реестр', 'Номер инспекции', 'Строка Excel', 'Дата Excel',
               'Полный путь в Sarex', 'folder_id / parent_id', 'Нужно создать папку',
               'Статус', 'Причина', 'Дата в имени PDF', 'Состояние папки', 'ID PDF в Sarex',
               'Код статуса', 'Все строки-кандидаты Excel']
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter=';', quoting=csv.QUOTE_ALL)
    writer.writerow(headers)
    rows = []
    for file in report['files']:
        values = [file['local_path'], file['registry_type'].upper().replace('SK', 'СК')
                  .replace('VK', 'ВК'), file['number'], file['row'], file['excel_date'],
                  file['full_path'],
                  f"folder_id={file['folder_id']}; parent_id={file['parent_id']}",
                  'Да' if file['need_folder'] else
                  'Не подтверждено' if file['parent_id'] else 'Нет',
                  file['status_description'], file['reason_description'],
                  (file['date_conflict'] or {}).get('pdf_date'),
                  describe(file['folder_status']) if file['folder_status'] else 'Не определена',
                  ', '.join(map(str, file['remote_document_ids'])), file['status'],
                  ', '.join(str(c['row']) for c in file['excel_candidates'])]
        values = ['' if v is None else str(v) for v in values]
        # Prefix only dangerous text, retaining numbers and ordinary names for filtering.
        writer.writerow(["'" + v if v.lstrip().startswith(('=', '+', '-', '@')) else v
                         for v in values])
        rows.append('| ' + ' | '.join(literal(v) for v in values[:10]) + ' |')
    lines = ['# Полный просмотр загрузки PDF', '',
             'Реальные файлы проверены по именам и метаданным. Исходники не менялись. '
             'Содержимое PDF не читалось. Принятие дерева для рабочих проверок: '
             + ('да' if report['tree']['operational_acceptance'][
                 'accepted_for_operational_checks'] else 'нет')
             + '. Абсолютная полнота не доказана. Реальная запись сейчас выключена.', '',
             '## Итоги', '', '| Показатель | Значение |', '|---|---:|']
    if report.get('local_moves_enabled'):
        lines[2] = ('Содержимое PDF не читалось и не изменялось. После сохранения этого плана '
                    'файлы с достоверно отсутствующим номером перемещаются в «не найдено». '
                    'Итоги каждого перемещения записываются отдельно: '
                    + report['local_moves_audit_directory'] + '. Sarex не изменяется; '
                    'реальная загрузка заблокирована.')
    labels = {'total_pdf': 'Всего локальных PDF',
              'matched_excel': 'Однозначно сопоставлены с Excel',
              'ready_to_upload': 'Разрешены к записи сейчас (режим выключен)',
              'ready_by_metadata': 'Однозначны по метаданным в существующих папках',
              'already_in_sarex': 'Совпадение имени/номера уже найдено в Sarex',
              'requires_folder': 'Подтверждённо требуется месячная папка',
              'missing_month_unconfirmed': 'Отсутствие месяца не подтверждено',
              'date_conflicts': 'Конфликт даты PDF и Excel', 'problem_files': 'Проблемные файлы',
              'uploaded': 'Загружено PDF', 'urls_written': 'URL сохранены в Excel',
              'already_confirmed': 'Подтверждены повторно без загрузки'}
    if report.get('mode') == 'PRODUCTION_UPLOAD':
        lines[0] = '# Результат загрузки PDF'
        lines[2] = ('PDF прочитаны последовательно для проверки подписи и SHA-256. '
                    'Результат каждой отправки подтверждается GET; URL сохраняется в переданный '
                    'Excel с резервной копией. Результаты создания папок — в ПАПКИ.md, '
                    'если список непуст. Абсолютная полнота '
                    'Gateway не доказана; принят остаточный риск завершённого обхода. '
                    + ('План отменён.' if report.get('cancelled') else
                       'Запуск остановлен; журнал не сбрасывайте.'
                       if report.get('stopped') else ''))
    lines += [f'| {labels[k]} | {v} |' for k, v in report['counts'].items()]
    if report.get('local_move_plan') and not report.get('local_moves_enabled'):
        lines += ['', '## План перемещения — не выполнен', '',
                  'Диагностика не перемещает PDF. Исходный и будущий путь:', '',
                  '| Исходный PDF | Будущий путь | Причина |', '|---|---|---|']
        for move in report['local_move_plan']:
            lines.append('| ' + ' | '.join(literal(move[k]) for k in
                                           ('source', 'destination', 'reason')) + ' |')
    lines += ['', 'Показатели могут пересекаться: конфликт даты сохраняется даже при '
              'отсутствующем месяце. «Однозначны по метаданным» не означает разрешение '
              'загрузки: нужны принятое дерево без ошибок, проверка содержимого PDF и приёмка.', '',
              'Покрытие: сопоставление Excel — '
              f"{report['coverage']['matched_excel_percent']}%; существующая конечная папка — "
              f"{report['coverage']['confirmed_folder_percent']}%. "
              + ('Результаты фактических операций приведены выше.'
                 if report.get('mode') == 'PRODUCTION_UPLOAD'
                 else 'Реальная запись выключена.'), '',
              '## Месяцы для возможного создания', '',
              '| Родитель | Последний подтверждённый месяц | Нужный месяц | Точное название | '
              'PDF всего / без ошибок сопоставления и дат | Ограничения |',
              '|---|---|---|---|---:|---|']
    for plan in report['planned_folders']:
        naming = plan['naming'] or {}
        values = [f"{plan['parent_full_path']} (ID {plan['parent_id']})",
                  naming.get('last_month_name', 'Схема не подтверждена: '
                             + describe(naming.get('status'))), plan['month'],
                  naming.get('name') or 'Не определено — ручная проверка',
                  f"{plan['pdf_count']} / {plan['waiting_without_conflict']}",
                  '; '.join(describe(c) for c in plan['creation_blockers'])]
        lines.append('| ' + ' | '.join(literal(v) for v in values) + ' |')
    lines += ['', 'Только необходимые месяцы. Промежуточные месяцы без PDF не планируются. '
              'Ручное подтверждение отсутствия не подтверждает полноту Gateway и '
              'не разрешает создание. Для неизвестного месяца folder_id отсутствует.', '',
              '## Все PDF', '', '[Полная таблица CSV](pdf_upload_preview.csv).', '',
              '| ' + ' | '.join(headers[:10]) + ' |', '|' + '---|' * 10]
    lines += rows
    lines += ['', '## Инспекция №12508', '']
    special = [f for f in report['files'] if f['number'] == '12508']
    for file in special:
        lines.append(literal({'filename': file['filename'], 'excel_row': file['row'],
                              'excel_date': file['excel_date'], 'path': file['full_path'],
                              'date_conflict': file['date_conflict'],
                              'status': file['status_description']}))
    if not special:
        lines.append('PDF №12508 не обнаружен в текущем локальном наборе. '
                     'Исторический пример не подменяет проверку отсутствующего файла.')
    lines += ['', 'Любой конфликт даты блокирует загрузку. Excel определяет только '
              'предполагаемое назначение. Автоматического разрешения конфликтов нет.', '',
              'Контрольная сумма плана: ' + report['plan_sha256'] + '.', '']
    diagnostics = '\n'.join(json.dumps({
        'локальный_pdf': f['local_path'], 'номер': f['number'], 'строка_excel': f['row'],
        'дата_excel': f['excel_date'], 'путь_sarex': f['full_path'],
        'ошибка_даты': f['date_conflict'], 'коды': f['reasons'],
        'проверки_имени_и_маршрута': f.get('filename_route_checks', []),
        'причины': f['reason_description'], 'загрузка_разрешена': f['ready_to_upload'],
    }, ensure_ascii=False) for f in report['files']) + '\n'
    return {'pdf_upload_preview.json': json.dumps(report, ensure_ascii=True, indent=2).encode(),
            'pdf_upload_preview.csv': stream.getvalue().encode('utf-8-sig'),
            'file-diagnostics.jsonl': diagnostics.encode('utf-8', errors='backslashreplace'),
            'PDF_UPLOAD_PREVIEW.md': '\n'.join(lines).encode()}
