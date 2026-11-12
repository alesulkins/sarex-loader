"""Multi-export local URL recovery: exact contextual index, reviewed copy, no API imports."""

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import date

from sarex_loader.api_models import ApiError, decode_payload
from sarex_loader.audit import audit_registry
from sarex_loader.excel_copy import URLUpdate, make_url_copy
from sarex_loader.file_safety import read_snapshot
from sarex_loader.folder_resolver import collision_key
from sarex_loader.gateway_models import MAX_GATEWAY_NODES, parse_gateway_search_documents
from sarex_loader.matching import extract_number, pdf_calendar_date
from sarex_loader.monthly_folders import filename_date_check
from sarex_loader.pdf_route_guard import VERSION as PDF_ROUTE_VERSION
from sarex_loader.pdf_route_guard import destination_check, filename_route_checks
from sarex_loader.reports import _write_bundle
from sarex_loader.safety import ValidationError

STATUSES = ('EXISTING_URL', 'MATCHED', 'AMBIGUOUS', 'NOT_FOUND_IN_EXPORT',
            'NOT_COVERED_BY_EXPORT', 'INVALID_DATA')
NUMBER_DUPLICATES = {'DUPLICATE_NUMBER', 'DUPLICATE_FOLDER_NUMBER',
                     'DUPLICATE_EXACT_DATE_NUMBER', 'DUPLICATE_NORMALIZATION_COLLISION'}


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _record_day(record):
    try:
        return date.fromisoformat(record['date'][:10]).isoformat()
    except (KeyError, TypeError, ValueError):
        return None


def _pagination(envelope, count):
    # Local acceptance policy for optional hints, not a claimed Gateway pagination schema.
    for key in ('count', 'total'):
        if key in envelope and (type(envelope[key]) is not int or envelope[key] < 0):
            raise ValidationError('INVALID_PAGINATION_METADATA: нужен ручной разбор.')
    if ('has_more' in envelope and type(envelope['has_more']) is not bool
            or 'next' in envelope and envelope['next'] is not None
            and type(envelope['next']) is not str):
        raise ValidationError('INVALID_PAGINATION_METADATA: нужен ручной разбор.')
    return {'completeness': 'UNKNOWN', 'metadata_contract_verified': False,
            'pagination_fields_present': any(k in envelope for k in
                                             ('next', 'count', 'total', 'has_more')),
            'more_pages_hint': bool(envelope.get('next')) or envelope.get('has_more') is True,
            'objects': count}


def _exports(config):
    documents, parents, covered, metadata = {}, {}, set(), []
    total_bytes = overlap = 0
    for entry in config.exports:
        raw = read_snapshot(entry['path'], config.limit)
        total_bytes += len(raw)
        if total_bytes > 32 * 1024**2 or _digest(raw) != entry['sha256']:
            raise ValidationError('EXPORT_CHANGED_OR_LIMIT: проверьте снимки выгрузок.')
        try:
            parsed = parse_gateway_search_documents(raw, max_response_bytes=config.limit)
            envelope = decode_payload(raw, max_nodes=MAX_GATEWAY_NODES)
        except ApiError:
            raise ValidationError('INVALID_EXPORT: некорректный Gateway JSON.') from None
        own = {d.id: d for d in parsed.documents}
        if any(i not in own or not own[i].is_folder for i in entry['folder_ids']):
            raise ValidationError('EXPORT_SCOPE_UNVERIFIED: нет объявленной папки в выгрузке.')
        covered.update(entry['folder_ids'])
        # Unknown Gateway pagination contract: these are hints, never proof of completeness.
        metadata.append(_pagination(envelope, len(own)))
        for d in parsed.documents:
            if d.id in documents:
                if documents[d.id] != d:
                    raise ValidationError('EXPORT_CONFLICT: разные данные одного ID.')
                overlap += 1
            documents[d.id] = d
            if len(documents) > 10000:
                raise ValidationError('EXPORT_LIMIT: превышен общий лимит объектов.')
            for index, identifier in enumerate(d.path_ids):
                parent = d.path_ids[index - 1] if index else None
                if identifier in parents and parents[identifier] != parent:
                    raise ValidationError('EXPORT_CONFLICT: несовместимая иерархия.')
                parents[identifier] = parent
    if any(p in documents and not documents[p].is_folder
           for p in parents.values() if p is not None):
        raise ValidationError('EXPORT_CONFLICT: файл указан как родитель.')
    return documents, covered, metadata, overlap


def _pdf_index(config, documents, covered):
    groups, normalized = defaultdict(list), defaultdict(set)
    stats = {i: {'folder_id': i, 'covered': i in covered, 'pdf_count': 0,
                 'invalid_pdf_names': 0, 'excel_rows': 0, 'empty_url_rows': 0,
                 'covered_empty_url_rows': 0,
                 'statuses': dict.fromkeys(STATUSES, 0)} for i in config.folders}
    for d in documents.values():
        if d.is_folder or len(d.path_ids) < 2 or not d.name.lower().endswith('.pdf'):
            continue
        folder = d.path_ids[-2]
        if folder not in covered:
            continue
        stats[folder]['pdf_count'] += 1
        kind = config.folders[folder][0]
        number = config.numbers[kind].get(d.name)
        if number is None:
            number = extract_number(d.name, config.separator)
        if number is None:
            stats[folder]['invalid_pdf_names'] += 1
            continue
        groups[(folder, number)].append(d.id)
        normalized[(folder, collision_key(number))].add(number)
    return groups, normalized, stats


def _records(config, registries):
    contexts = (config.context_folders if config.context_folders is not None
                else {context: i for i, context in config.folders.items()})
    entries, groups, normalized = [], defaultdict(list), defaultdict(set)
    for source, registry in enumerate(registries):
        invalid = set()
        blocked = registry['status'] == 'REJECTED'
        for issue in registry['issues']:
            if issue['severity'] != 'error' or issue['code'] in NUMBER_DUPLICATES:
                continue
            for location in issue.get('locations') or [issue]:
                if location.get('row') in (None, 1):
                    blocked = True
                else:
                    invalid.add((location.get('sheet'), location['row']))
        for record in registry['records']:
            context = (registry['registry_type'], record['office'], record['contractor'],
                       record['month'])
            number = record['number']
            # Do not select a suffix grammar that can truncate an actual registry number.
            bad_number = not isinstance(number, str) or not number
            if not bad_number and config.separator in number:
                raise ValidationError('Разделитель встречается внутри номера реестра.')
            item = {'source': source, 'record': record,
                    'folder': contexts.get(context), 'context': context,
                    'invalid': blocked or (record['sheet'], record['row']) in invalid
                    or bad_number or not record.get('id_key')}
            entries.append(item)
            if not bad_number:
                groups[(*context, number)].append(item)
                normalized[(*context, collision_key(number))].add(number)
    return entries, groups, normalized


def run_recovery(config, *, output_dir=None, write_copy=False, expected_plan_sha256=None,
                 read_tree=False, tree_index=None, require_complete_children=False,
                 write_original=False, backup_dir=None):
    """Preview never writes Excel. Applying requires the reviewed plan hash and URL consent.

    MATCHED means unique in explicitly scoped local exports, not verified on the server.
    Reports contain aggregates/IDs only; row metadata and document names remain in RAM.
    """
    from sarex_loader.tree_source import validate_tree_mode

    validate_tree_mode(config.tree, read_tree)
    if type(write_copy) is not bool or type(write_original) is not bool or (
            write_copy and write_original):
        raise ValidationError('Некорректный режим восстановления.')
    applying = write_copy or write_original
    if applying and (output_dir is None or not config.url_contract_confirmed):
        raise ValidationError('Для копии нужны каталог, preview и подтверждённый URL-контракт.')
    if write_original and (backup_dir is None or len(config.registries) != 1):
        raise ValidationError('Для записи нужны резервный каталог и один реестр СК или ВК.')
    if write_original and (output_dir.exists() or output_dir.is_symlink()
                           or output_dir.is_relative_to(config.root)
                           or config.root.is_relative_to(output_dir)):
        raise ValidationError('Перед записью Excel нужен новый отдельный каталог отчётов.')
    registries = [audit_registry(c) for c in config.registries]
    tree_info = None
    folder_problems = {}
    if config.tree is not None:
        config, tree_index, folder_problems = _resolve_tree(
            config, registries, read_tree, tree_index=tree_index)
        from sarex_loader.tree_source import tree_summary

        tree_info = tree_summary(config.tree, tree_index)
        documents = tree_index.documents
        # Local exports prove observed objects, not absence; browser additionally
        # requires an actual request for the terminal folder, not just a breadcrumb.
        covered = set(config.folders)
        if (config.tree.source == 'browser' or config.tree.queried_folder_ids is not None
                or tree_index.observation is not None):
            covered &= tree_index.queried_folders
        metadata, overlap = tree_index.metadata, tree_index.overlap
    else:
        documents, covered, metadata, overlap = _exports(config)
    pdfs, pdf_normalized, folder_stats = _pdf_index(config, documents, covered)
    entries, rows, row_normalized = _records(config, registries)
    # Explicit aliases or shared office/month layouts may merge source contexts.
    # A number occurring twice in that destination must never select the same PDF.
    destination_numbers = Counter((i['folder'], collision_key(i['record']['number']))
                                  for i in entries if i['folder'] is not None
                                  and isinstance(i['record']['number'], str))
    context_days = Counter((i['context'], i['record']['number'], _record_day(i['record']))
                           for i in entries if isinstance(i['record']['number'], str))
    destination_days = Counter((i['folder'], collision_key(i['record']['number']),
                                _record_day(i['record'])) for i in entries
                               if i['folder'] is not None
                               and isinstance(i['record']['number'], str))
    pdf_days = defaultdict(list)
    for (folder, number), identifiers in pdfs.items():
        for identifier in identifiers:
            day = pdf_calendar_date(documents[identifier].name)
            pdf_days[folder, number, day].append(identifier)
    # Audit retains only URL hashes. A PDF already assigned anywhere in these registries
    # cannot also be used to fill a different row, even if that row has a different number.
    existing_urls = {r['url_hash'] for registry in registries for r in registry['records']
                     if r['url_hash'] is not None}
    already_assigned = {identifier for identifier in documents if _digest(
        f'https://lk.sarex.io/documentations/{identifier}'.encode()) in existing_urls}
    updates = defaultdict(list)
    ids = defaultdict(list)
    candidates = []
    sheet_indices = [{sheet['name']: i + 1 for i, sheet in enumerate(registry['sheets'])}
                     for registry in registries]
    summary = dict.fromkeys(STATUSES, 0)
    empty = covered_empty = 0
    row_issues = []
    observed_candidates = []
    for item in entries:
        row_problem = None
        record, folder = item['record'], item['folder']
        number, context = record['number'], item['context']
        is_empty = record['url_class'] == 'EMPTY'
        empty += is_empty
        covered_empty += is_empty and folder in covered
        row_checks = []
        day = _record_day(record)
        destination_key = (folder, collision_key(number)) if isinstance(number, str) else (None, '')
        context_count = len(rows[(*context, number)]) if isinstance(number, str) else 0
        all_ids = pdfs[(folder, number)] if isinstance(number, str) else []
        date_required = (context_count > 1 or destination_numbers[destination_key] > 1
                         or len(all_ids) > 1)
        matches = all_ids
        if date_required:
            # Only a valid, exact day can distinguish repeated numbers. An undated
            # candidate remains potentially conflicting and cannot be discarded.
            matches = (pdf_days[folder, number, day]
                       if day and not pdf_days[folder, number, None] else [])
        context_unique = (context_count == 1 or day and not context_days[context, number, None]
                          and context_days[context, number, day] == 1)
        destination_unique = (destination_numbers[destination_key] <= 1 or day
                              and not destination_days[*destination_key, None]
                              and destination_days[*destination_key, day] == 1)
        if isinstance(number, str) and folder in covered and len(matches) == 1:
            document = documents[matches[0]]
            rules = (config.routes or {}).get(context[0])
            if rules:
                row_checks = filename_route_checks(document.name, record, rules.root_id)
                if check := destination_check(rules.root_id, record, document.path_ids[:-1]):
                    row_checks.append(check)
            if check := filename_date_check(document.name, record['date']):
                row_checks.append(check)
        if not is_empty:
            status = 'EXISTING_URL'
        elif item['invalid']:
            status = 'INVALID_DATA'
        elif (not context_unique
              or len(row_normalized[(*context, collision_key(number))]) != 1
              or not destination_unique):
            status = 'AMBIGUOUS'
        elif folder_problems.get(context) in {'AMBIGUOUS_FOLDER', 'AMBIGUOUS_ROUTE'}:
            status = 'AMBIGUOUS'
        elif folder not in covered:
            status = 'NOT_COVERED_BY_EXPORT'
        elif (len(matches) > 1 or date_required and all_ids and len(matches) != 1
              or len(pdf_normalized[(folder, collision_key(number))]) > 1):
            status = 'AMBIGUOUS'
        elif not matches:
            status = 'NOT_FOUND_IN_EXPORT'
        elif matches[0] in already_assigned:
            status = 'AMBIGUOUS'
        elif row_checks:
            status = 'INVALID_DATA'
            row_problem = row_checks[0]['code']
        elif require_complete_children and tree_info and not (
                tree_info['operational_acceptance']['accepted_for_operational_checks']):
            status = 'NOT_COVERED_BY_EXPORT'
            observed_candidates.append({'registry_type': context[0], 'row': record['row'],
                'folder_id': folder, 'document_id': matches[0],
                'reason': 'TREE_COMPLETENESS_UNVERIFIED'})
            row_problem = 'TREE_COMPLETENESS_UNVERIFIED'
        else:
            status = 'MATCHED'
            identifier = matches[0]
            ids[item['source']].append(identifier)
            updates[item['source']].append(URLUpdate(
                record['sheet'], record['row'], record['id_key'], number,
                f'https://lk.sarex.io/documentations/{identifier}'))
            candidates.append({'registry_type': context[0],
                               'sheet_index': sheet_indices[item['source']][record['sheet']],
                               'row': record['row'], 'folder_id': folder,
                               'document_id': identifier})
        if (tree_info is not None and config.tree.source == 'gateway'
                and status not in {'MATCHED', 'EXISTING_URL'}):
            row_issues.append({
                'registry_index': item['source'],
                'sheet_index': sheet_indices[item['source']][record['sheet']],
                'row': record['row'], 'status': status,
                'reason': row_problem or folder_problems.get(context, status),
                'checks': row_checks})
        summary[status] += 1
        if folder is not None:
            s = folder_stats[folder]
            s['excel_rows'] += 1
            s['empty_url_rows'] += is_empty
            s['covered_empty_url_rows'] += is_empty and folder in covered
            s['statuses'][status] += 1
    # Seal exact input bytes and matching policy; no private policy values enter the report.
    seal = {'pdf_route_guard': PDF_ROUTE_VERSION,
            'registries': [(c.inspection_type, r['sha256']) for c, r in
                           zip(config.registries, registries, strict=True)],
            'exports': [(e['sha256'], e['folder_ids']) for e in config.exports],
            'folders': config.folders, 'separator': config.separator, 'numbers': config.numbers,
            'candidates': candidates, 'summary': summary,
            'url_contract_confirmed': config.url_contract_confirmed, 'algorithm': 1}
    if require_complete_children:
        seal['require_complete_children'] = True
        seal['observed_candidates_pending_completeness'] = observed_candidates
    if tree_info is not None:
        seal['tree'] = tree_info['sha256']
        seal['operational_acceptance'] = tree_info['operational_acceptance']
        seal['routes'] = {kind: {'root_id': route.root_id, 'prefix': route.prefix,
                                'offices': route.offices, 'contractors': route.contractors,
                                'inspection_folder': route.inspection_folder}
                          for kind, route in config.routes.items()}
        for kind, route in config.routes.items():
            if route.layouts:
                seal['routes'][kind]['layouts'] = route.layouts
    plan = _digest(json.dumps(seal, sort_keys=True, ensure_ascii=True).encode())
    if applying and expected_plan_sha256 != plan:
        raise ValidationError('PLAN_CHANGED: нужен SHA256 актуального preview.')
    report = {'mode': 'LOCAL_RECOVERY', 'network_enabled': False,
              'source_write_enabled': write_original, 'excel_written': write_copy,
              'plan_sha256': plan, 'summary': summary,
              'empty_url_rows': empty, 'covered_empty_url_rows': covered_empty,
              'uncovered_empty_url_rows': empty - covered_empty,
              'folders': [folder_stats[i] for i in sorted(folder_stats)],
              'candidates': candidates,
              'registries': [{'inspection_type': r['registry_type'], 'status': r['status'],
                              'rows': len(r['records']),
                              'errors': sum(i['severity'] == 'error' for i in r['issues'])}
                             for r in registries],
              'exports': metadata, 'unique_objects': len(documents), 'overlap_objects': overlap,
              'server_completeness': 'UNKNOWN', 'absence_proves_no_document': False,
              'url_server_verified': False}
    if require_complete_children:
        report['observed_candidates_pending_completeness'] = observed_candidates
        report['require_complete_children'] = True
    if tree_info is not None:
        report.update(mode='TREE_RECOVERY', tree=tree_info,
                      network_enabled=tree_info['network_enabled'],
                      folder_resolution_issues=dict(Counter(folder_problems.values())))
        if config.tree.source == 'gateway':
            report['row_issues'] = row_issues
    payloads = {}
    if tree_info is not None:
        from sarex_loader.tree_source import snapshot_payloads, tree_snapshot

        snapshot = tree_snapshot(config.tree, tree_index)
        if snapshot is not None:
            payloads.update(snapshot_payloads(snapshot, config.tree.max_response_bytes))
    for index, (c, r) in enumerate(zip(config.registries, registries, strict=True)):
        raw = read_snapshot(c.excel, c.max_file_bytes)
        if _digest(raw) != r['sha256']:
            raise ValidationError('INPUT_CHANGED: книга изменилась после аудита.')
        if write_copy:
            payloads[f'registry-{c.inspection_type}.xlsx'] = make_url_copy(
                raw, r['sha256'], updates[index], approved_document_ids=tuple(ids[index]))
    # Recheck every source immediately before publishing; no source file is ever opened writable.
    for c, r in zip(config.registries, registries, strict=True):
        if _digest(read_snapshot(c.excel, c.max_file_bytes)) != r['sha256']:
            raise ValidationError('INPUT_CHANGED: повторная проверка книги не пройдена.')
    for e in config.exports:
        if _digest(read_snapshot(e['path'], config.limit)) != e['sha256']:
            raise ValidationError('EXPORT_CHANGED: повторная проверка выгрузки не пройдена.')
    if config.tree is not None:
        config.tree.verify_sources()
    if write_original:
        from sarex_loader.excel_commit import commit_urls

        c = config.registries[0]
        receipt = commit_urls(c.excel, raw, updates[0], backup_dir=backup_dir,
                              approved_document_ids=tuple(ids[0]))
        report['excel_commit'] = receipt
        report['excel_written'] = receipt['disk_verified']
        report['urls_written'] = receipt['urls_written']
    if output_dir is not None:
        from sarex_loader.russian_reports import recovery_csv

        payloads.update(recovery_csv(report))
        payloads['recovery.json'] = json.dumps(report, ensure_ascii=True, indent=2).encode()
        _write_bundle(output_dir, payloads, [config.root])
        if write_copy:
            report['excel_written'] = True
    return report


def _resolve_tree(config, registries, allow_browser, *, tree_index=None):
    from sarex_loader.tree_source import read_tree

    paths, contexts, problems = set(), {}, {}
    for registry in registries:
        kind = registry['registry_type']
        rules = config.routes[kind]
        for record in registry['records']:
            # Invalid non-text cells are handled by the existing audit/row validator.
            if not all(isinstance(record[k], str) for k in ('office', 'contractor', 'month')):
                continue
            context = (kind, record['office'], record['contractor'], record['month'])
            proposal, error = rules.propose(record)
            if error:
                problems[context] = error
                continue
            key = (int(rules.root_id), tuple(proposal['components']))
            contexts[context] = key
            if record['url_class'] == 'EMPTY':
                paths.add(key)
    index = tree_index if tree_index is not None else read_tree(
        config.tree, paths, allow_browser=allow_browser)
    from sarex_loader.tree_source import resolve_observed_path

    results = {key: resolve_observed_path(index, *key) for key in set(contexts.values())}
    folders, context_folders = {}, {}
    blocked_folders = set()
    for context, key in contexts.items():
        result = results[key]
        if result.folder_id is None:
            problems[context] = result.status
        elif check := destination_check(key[0], {
                'office': context[1], 'contractor': context[2]}, result.path_ids):
            problems[context] = check['code']
        elif result.folder_id in blocked_folders:
            problems[context] = 'AMBIGUOUS_FOLDER'
        else:
            previous = folders.get(result.folder_id)
            if previous is not None and previous != context and (
                    not config.routes[context[0]].layouts or previous[0] != context[0]
                    or previous[3] != context[3]):
                if config.tree.source != 'gateway':
                    raise ValidationError(
                        'TREE_CONTEXT_CONFLICT: одна папка для разных контекстов.')
                blocked_folders.add(result.folder_id)
                problems[context] = 'AMBIGUOUS_FOLDER'
                for other in [c for c, folder in context_folders.items()
                              if folder == result.folder_id]:
                    problems[other] = 'AMBIGUOUS_FOLDER'
                    del context_folders[other]
                del folders[result.folder_id]
                continue
            folders.setdefault(result.folder_id, context)
            context_folders[context] = result.folder_id
    return replace(config, folders=folders, context_folders=context_folders), index, problems
