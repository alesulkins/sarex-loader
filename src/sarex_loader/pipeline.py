"""Audit/matching/target plan with optional read-only tree discovery; no uploader."""

import hashlib
import os
from collections import Counter, defaultdict

from sarex_loader.audit import audit_registry
from sarex_loader.file_safety import directory_fd, read_snapshot
from sarex_loader.folder_resolver import FolderRules, collision_key
from sarex_loader.journal import Journal, fingerprint
from sarex_loader.matching import InspectionIndex, build_match_report, extract_number
from sarex_loader.monthly_folders import filename_date_check
from sarex_loader.pdf_route_guard import VERSION as PDF_ROUTE_VERSION
from sarex_loader.pdf_route_guard import destination_check
from sarex_loader.pdf_scan import identity, scan_pdfs
from sarex_loader.safety import ValidationError

RULE_VERSION = 'stage5-exact-filename-v2'


def _row_status(index, candidate):
    if candidate['existing_url']:
        return 'EXISTING_URL'
    if candidate['reasons'] or candidate['registry_type'] in index.blocked_types:
        return 'INVALID_DATA'
    category, _ = index.lookup(candidate['registry_type'], candidate['number'])
    return 'AMBIGUOUS' if category == 'AMBIGUOUS' else 'NEEDS_REMOTE_CHECK'


def _verify_sources(config, registry, files, directory_identity):
    if config.tree is not None:
        config.tree.verify_sources()
    current = hashlib.sha256(read_snapshot(config.excel, config.max_file_bytes)).hexdigest()
    if registry['sha256'] != current:
        raise ValidationError('INPUT_CHANGED: исходный Excel изменился после аудита.')
    if directory_identity is None:
        return
    with directory_fd(config.pdf_dir) as fd:
        if identity(os.fstat(fd)) != directory_identity:
            raise ValidationError('INPUT_CHANGED: каталог PDF изменился после сканирования.')
        for item in files:
            if item['identity'] is not None:
                try:
                    info = os.stat(item['filename'], dir_fd=fd, follow_symlinks=False)
                except OSError:
                    raise ValidationError('INPUT_CHANGED: PDF недоступен.') from None
                if list(identity(info)) != item['identity']:
                    raise ValidationError('INPUT_CHANGED: PDF изменился после сканирования.')


def run_pipeline(config, *, read_tree=False, pdf_metadata_only=False) -> dict:
    from sarex_loader.tree_source import validate_tree_mode

    validate_tree_mode(config.tree, read_tree)
    if pdf_metadata_only:
        return build_plan(config, read_tree=read_tree, pdf_metadata_only=True)
    if config.command not in {'upload', 'fill-urls'} or config.journal_dir is None:
        raise ValidationError('Для конвейера нужен явный journal_dir вне исходных данных.')
    # Acquire the run lock before reading the workbook or reserving any plan.
    with Journal(config.journal_dir, [config.input_root]) as journal:
        return build_plan(config, journal, read_tree=read_tree)


def build_plan(config, journal: Journal | None = None, *, read_tree=False,
               check_existing_documents=True, pdf_metadata_only=False) -> dict:
    """Build a local plan; register only when a caller supplies its locked journal."""
    if type(pdf_metadata_only) is not bool or pdf_metadata_only and journal is not None:
        raise ValidationError('METADATA_PLAN_CANNOT_REGISTER_UPLOAD')
    rules = FolderRules(config.target_folder_id, config.office_folders,
                        config.contractor_folders, config.inspection_folder, config.folder_prefix,
                        config.folder_routes)
    registry = audit_registry(config)
    index = InspectionIndex([registry], {config.inspection_type: rules})
    tree = None
    tree_info = None
    resolutions = {}
    remote_numbers, remote_names = defaultdict(set), defaultdict(set)
    if config.tree is not None:
        from sarex_loader.tree_source import read_tree as load_tree
        from sarex_loader.tree_source import resolve_observed_path, tree_summary

        paths = {(int(rules.root_id), tuple(c['proposed_folder']['components']))
                 for c in index.candidates if c['proposed_folder'] and not c['existing_url']
                 and not c['reasons']}
        tree = load_tree(config.tree, paths, allow_browser=read_tree)
        all_paths = {(int(rules.root_id), tuple(c['proposed_folder']['components']))
                     for c in index.candidates if c['proposed_folder']}
        resolutions = {parts: resolve_observed_path(tree, root, parts) for root, parts in all_paths}
        tree_info = tree_summary(config.tree, tree)
        for document in tree.documents.values():
            if document.is_folder or len(document.path_ids) < 2:
                continue
            parent = document.path_ids[-2]
            remote_names[(parent, collision_key(document.name))].add(document.id)
            number = (config.filename_numbers or {}).get(document.name)
            if number is None:
                number = extract_number(document.name, config.filename_separator)
            if number is not None:
                remote_numbers[(parent, collision_key(number))].add(document.id)
    directory_identity = None
    matched = None
    files = []
    if config.command == 'upload':
        with directory_fd(config.pdf_dir) as fd:
            directory_identity = identity(os.fstat(fd))
        # Metadata only; PDF content is streamed once. Stable presentation costs M log M;
        # inspection indexing and hash lookups remain expected O(N + M).
        scanned = (scan_pdfs(config.pdf_dir, metadata_only=True) if pdf_metadata_only
                   else scan_pdfs(config.pdf_dir))
        entries = sorted(scanned, key=lambda e: e['filename'])
        matched = build_match_report(index, entries, config.inspection_type,
                                     config.filename_separator, config.filename_numbers)
        files = matched['files']
    rows = [{**candidate, 'status': _row_status(index, candidate),
             'flags': ['TARGET_UNVERIFIED'] if candidate['proposed_folder'] else []}
            for candidate in index.candidates]
    if tree is not None:
        for row in rows:
            proposal = row['proposed_folder']
            result = resolutions.get(tuple(proposal['components'])) if proposal else None
            if result is not None:
                row['folder_resolution'] = result.status
                row['resolved_folder_id'] = result.folder_id
                row['resolved_path_ids'] = list(result.path_ids)
                row['resolved_path_names'] = [tree.documents[i].name for i in result.path_ids
                                              if i in tree.documents]
                row['flags'] = ['SNAPSHOT_ONLY_SERVER_COMPLETENESS_UNKNOWN']
    if matched is not None:
        local_groups = Counter(f['candidate_group'] for f in files
                               if f['candidate_group'] is not None)
        for group_id, group in enumerate(index.groups):
            for candidate_id in group['candidate_ids']:
                rows[candidate_id]['local_pdf_status'] = (
                    'PRESENT_REQUIRES_REVIEW' if local_groups[group_id] else 'NOT_FOUND')
    operations = {}
    scope = fingerprint({'registry': str(config.excel), 'type': config.inspection_type})
    rule_hash = fingerprint({'version': RULE_VERSION, 'root': rules.root_id,
                             'pdf_route_guard': PDF_ROUTE_VERSION,
                             'offices': rules.offices, 'contractors': rules.contractors,
                             'inspection_folder': rules.inspection_folder,
                             'separator': config.filename_separator,
                             'filename_numbers': config.filename_numbers or {}})
    if tree is not None:
        rule_hash = fingerprint({'legacy_rules': rule_hash, 'prefix': rules.prefix,
                                 'tree': tree_info['sha256']})
    if rules.layouts:
        rule_hash = fingerprint({'legacy_rules': rule_hash, 'layouts': rules.layouts})
    for file in files:
        category = file['category']
        status = {'MATCHED': 'LOCAL_MATCH', 'INVALID_FILENAME': 'INVALID_DATA',
                  'INVALID_REGISTRY_DATA': 'INVALID_DATA'}.get(category, category)
        candidate = None
        members = []
        if file['candidate_group'] is not None:
            members = index.groups[file['candidate_group']]['candidate_ids']
            if len(members) == 1:
                candidate = index.candidates[members[0]]
            if candidate and candidate['existing_url'] and category == 'MATCHED':
                status = 'EXISTING_URL'
        resolution = None
        if tree is not None and status == 'LOCAL_MATCH':
            resolution = resolutions[tuple(candidate['proposed_folder']['components'])]
            if resolution.folder_id is None:
                status = resolution.status
            elif (check := destination_check(rules.root_id, candidate, resolution.path_ids)):
                status = check['code']
                file['reasons'].append(status)
                file['filename_route_checks'].append(check)
            elif check_existing_documents and (
                    remote_names.get((resolution.folder_id, collision_key(file['filename'])))
                    or remote_numbers.get((resolution.folder_id, collision_key(file['number'])))):
                status = 'REMOTE_DOCUMENT_EXISTS'
            elif (tree.observation is not None
                  and resolution.folder_id not in tree.queried_folders):
                status = 'TREE_FOLDER_NOT_QUERIED'
        if pdf_metadata_only and status == 'LOCAL_MATCH':
            status = 'PDF_CONTENT_NOT_VERIFIED'
        date_checks = [{**check, 'sheet': index.candidates[i]['sheet'],
                        'row': index.candidates[i]['row']}
                       for i in members
                       if (check := filename_date_check(file['filename'],
                                                        index.candidates[i]['date']))]
        date_conflict = (filename_date_check(file['filename'], candidate['date'])
                         if candidate else filename_date_check(file['filename'], None))
        file['reasons'] += [check['code'] for check in date_checks]
        if candidate:
            file['reasons'] += candidate['reasons']
        if date_conflict:
            status = date_conflict['code']
            file['reasons'].append(status)
            if candidate and candidate['proposed_folder'] and not file['proposed_path']:
                file['proposed_path'] = {**candidate['proposed_folder'], 'components': [
                    *candidate['proposed_folder']['components'], file['filename']]}
        payload = {
            'registry_type': config.inspection_type, 'registry_scope': scope,
            'row_id': candidate['id'] if candidate else None,
            'sheet': candidate['sheet'] if candidate else None,
            'row': candidate['row'] if candidate else None,
            'filename_route_checks': file.get('filename_route_checks', []),
            'number': file['number'], 'filename': file['filename'],
            'pdf_sha256': file['sha256'], 'target_folder_id': rules.root_id,
            'proposed_path': file['proposed_path'], 'rule_version': RULE_VERSION,
            'rule_fingerprint': rule_hash, 'status': status,
            'origin_fingerprint': fingerprint('OFFLINE_NO_SERVER_CONFIGURED'),
        }
        if date_conflict:
            payload['date_conflict'] = {
                **date_conflict, 'filename': file['filename'], 'number': file['number'],
                'sheet': candidate['sheet'] if candidate else None,
                'row': candidate['row'] if candidate else None,
                'excel_destination': file['proposed_path'],
            }
        file['reasons'] = list(dict.fromkeys(file['reasons']))
        if tree is not None:
            payload.update(resolved_folder_id=resolution.folder_id if resolution else None,
                           resolved_path_ids=list(resolution.path_ids) if resolution else [],
                           tree_sha256=tree_info['sha256'], disk_id=config.tree.disk_id)
            file['resolved_folder_id'] = payload['resolved_folder_id']
        key = fingerprint({k: v for k, v in payload.items() if k != 'filename'})
        # Repeated bytes/IDs already cause AMBIGUOUS. Keep separate blocked diagnostics.
        if status != 'LOCAL_MATCH':
            key = fingerprint({'operation': key, 'filename': file['filename']})
        operations[key] = payload
        file['operation_id'] = key
        file['local_status'] = status
        file['flags'] = (['TARGET_UNVERIFIED', 'NEEDS_REMOTE_CHECK']
                         if status == 'LOCAL_MATCH' else [])
    if config.command == 'fill-urls':
        for candidate in rows:
            payload = {
                'registry_type': config.inspection_type, 'registry_scope': scope,
                'row_id': candidate['id'], 'sheet': candidate['sheet'], 'row': candidate['row'],
                'number': candidate['number'], 'pdf_sha256': None,
                'target_folder_id': rules.root_id,
                'proposed_path': candidate['proposed_folder'],
                'rule_version': RULE_VERSION, 'rule_fingerprint': rule_hash,
                'origin_fingerprint': fingerprint('OFFLINE_NO_SERVER_CONFIGURED'),
                'status': candidate['status'],
            }
            key = fingerprint(payload)
            candidate['operation_id'] = key
            operations[key] = payload
    context = {'command': config.command, 'registry_scope': scope,
               'registry_sha256': registry['sha256'], 'rules': rule_hash,
               'pdf_directory': str(config.pdf_dir) if config.command == 'upload' else None,
               'pdf_manifest': [{k: item[k] for k in
                                 ('filename', 'sha256', 'size', 'identity', 'reason')}
                                for item in files]}
    _verify_sources(config, registry, files, directory_identity)
    if config.tree is not None:
        config.tree.verify_sources()
    if pdf_metadata_only:
        context['pdf_metadata_only'] = True
    checkpoints = (journal.register(context, operations) if journal is not None else {
        key: {'state': 'PLANNED' if item['status'] == 'LOCAL_MATCH' else 'BLOCKED',
              'phase': None, 'bundle_id': None, 'document_id': None, 'url_status': 'UNVERIFIED'}
        for key, item in operations.items()})
    counts = Counter(value['status'] for value in operations.values())
    unknown = sum(c['state'] == 'OUTCOME_UNKNOWN' for c in checkpoints.values())
    issues = (registry['status'] != 'CLEAN' or index.blocked_types or unknown
              or any(c['status'] in {'INVALID_DATA', 'AMBIGUOUS'} for c in rows)
              or any(k in {'INVALID_DATA', 'AMBIGUOUS', 'NOT_FOUND'}
                     or 'FOLDER' in k or k.startswith(('ROOT_', 'REMOTE_')) for k in counts))
    report = {
        'schema_version': 1, 'stage': 5, 'command': config.command,
        'dry_run': True, 'network_enabled': False, 'write_enabled': False,
        'upload_authorized': False, 'source_write_enabled': False,
        'status': 'ISSUES' if issues else 'LOCAL_PLAN_ONLY',
        'plan_id': fingerprint(context), 'rule_version': RULE_VERSION,
        'url_policy': {'preferred_format': 'documentations/{id}',
                       'api_id_relationship_verified': False, 'generated_urls': []},
        'registry': registry, 'rows': rows, 'matching': matched,
        'pdf_directory_identity': directory_identity,
        'operations': operations, 'mock_checkpoints': checkpoints,
        'summary': dict(counts), 'outcome_unknown': unknown,
        'row_summary': dict(Counter(c['status'] for c in rows)),
        'metrics': {'rows_indexed': index.rows_indexed, 'entries_scanned': len(files),
                    'hash_lookups': index.lookups},
    }
    if pdf_metadata_only:
        report.update(pdf_metadata_only=True, journal_updated=False,
                      pdf_contents_read=False, content_duplicate_check='NOT_PERFORMED')
    if tree_info is not None:
        from sarex_loader.tree_source import tree_snapshot

        report['tree'] = tree_info
        report['network_enabled'] = tree_info['network_enabled']
        snapshot = tree_snapshot(config.tree, tree)
        if snapshot is not None:
            report['tree_snapshot'] = snapshot
    return report
