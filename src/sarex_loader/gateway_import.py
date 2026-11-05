"""Offline script-2 candidates from a bounded Gateway snapshot. No HTTP or XLSX writes."""

import hashlib
from collections import Counter, defaultdict

from sarex_loader.api_models import ApiError, valid_id
from sarex_loader.audit import audit_registry
from sarex_loader.file_safety import read_snapshot
from sarex_loader.folder_resolver import FolderRules, collision_key, safe_component
from sarex_loader.gateway_models import (
    GatewayDocuments,
    GatewaySearchDocument,
    parse_gateway_search_documents,
)
from sarex_loader.matching import (
    InspectionIndex,
    extract_number,
    validate_filename_numbers,
    validate_separator,
)
from sarex_loader.safety import ValidationError

KNOWN_PDF_IDS = (6316681, 6391677)


class GatewaySearchIndex:
    """Expected O(P + D) construction; parent/name and (type,parent,number) hash lookups.

    Unicode keys only detect ambiguity. They never select or normalize a match.
    Shared groups prevent large duplicate buckets being copied into every Excel row.
    """

    def __init__(self, documents: GatewayDocuments[GatewaySearchDocument], kind: str,
                 root_id: int, separator: str, filename_numbers: dict | None):
        if not valid_id(root_id) or kind not in {'sk', 'vk', 'geodetic'}:
            raise ValidationError('Нужны допустимые тип реестра и ID корневой папки.')
        validate_separator(separator)
        explicit = validate_filename_numbers(filename_numbers)
        self.by_id = {d.id: d for d in documents.documents}
        self.root_id, self.kind = root_id, kind
        self.folder_lookups = self.number_lookups = 0
        self.folder_groups = []
        self.document_groups = []
        self._folders = defaultdict(list)
        self._folder_collisions = defaultdict(list)
        self._folder_results = {}
        self._numbers = {}
        self.issues = []
        self.missing_ancestor_ids = set()
        self.scope_ids = set()
        self.pdf_count = 0
        self.invalid_pdf_count = 0
        names = defaultdict(list)
        normalized_numbers = defaultdict(list)
        for document in documents.documents:
            for ancestor in document.path_ids[:-1]:
                parent = self.by_id.get(ancestor)
                if parent is None:
                    self.missing_ancestor_ids.add(ancestor)
                elif not parent.is_folder:
                    raise ValidationError('GATEWAY_TYPE_CONFLICT: файл указан предком объекта.')
            if root_id not in document.path_ids[:-1]:
                continue
            self.scope_ids.add(document.id)
            parent_id = document.path_ids[-2]
            if document.is_folder:
                self._folders[(parent_id, document.name)].append(document.id)
                self._folder_collisions[(parent_id, collision_key(document.name))].append(
                    document.id)
                continue
            if not document.name.lower().endswith('.pdf'):
                continue
            self.pdf_count += 1
            names[(parent_id, collision_key(document.name))].append(document.id)
            number = (explicit[document.name] if document.name in explicit
                      else extract_number(document.name, separator))
            if number is None:
                self.invalid_pdf_count += 1
                self.issues.append({'document_id': document.id, 'code': 'INVALID_FILENAME'})
                continue
            key = (kind, parent_id, number)
            if key not in self._numbers:
                self._numbers[key] = len(self.document_groups)
                self.document_groups.append({
                    'group_id': self._numbers[key], 'folder_id': parent_id,
                    'document_ids': [], 'candidate_urls': [], 'ambiguous': False,
                    'url_relationship_verified': False,
                })
            group_id = self._numbers[key]
            group = self.document_groups[group_id]
            group['document_ids'].append(document.id)
            group['candidate_urls'].append(f'https://lk.sarex.io/documentations/{document.id}')
            normalized_numbers[(parent_id, collision_key(number))].append(group_id)
        collisions = {identifier for ids in names.values() if len(ids) > 1 for identifier in ids}
        for ids in normalized_numbers.values():
            if len(ids) > 1:
                for group_id in ids:
                    self.document_groups[group_id]['ambiguous'] = True
        for group in self.document_groups:
            if (len(group['document_ids']) > 1
                    or any(i in collisions for i in group['document_ids'])):
                group['ambiguous'] = True
        root = self.by_id.get(root_id)
        if root is not None and not root.is_folder:
            raise ValidationError('GATEWAY_ROOT_NOT_FOLDER: выбранный ID не является папкой.')

    def folder(self, components: list[str]) -> tuple[int | None, int | None]:
        current = self.root_id
        for component in components:
            self.folder_lookups += 1
            key = (current, component)
            if key not in self._folder_results:
                ids = self._folders.get(key, [])
                similar = self._folder_collisions.get((current, collision_key(component)), [])
                if len(ids) != 1 or len(similar) > 1:
                    group_id = len(self.folder_groups)
                    self.folder_groups.append({
                        'group_id': group_id, 'parent_id': current,
                        'folder_ids': list(similar),
                        'status': 'AMBIGUOUS_FOLDER' if len(similar) > 1
                        else 'FOLDER_NOT_RESOLVED_IN_EXPORT',
                    })
                    self._folder_results[key] = (None, group_id)
                else:
                    self._folder_results[key] = (ids[0], None)
            identifier, problem = self._folder_results[key]
            if problem is not None:
                return None, problem
            current = identifier
        return current, None

    def lookup(self, kind: str, parent_id: int, number: str) -> int | None:
        self.number_lookups += 1
        return self._numbers.get((kind, parent_id, number))

    def known_documents(self) -> list[dict]:
        result = []
        for identifier in KNOWN_PDF_IDS:
            document = self.by_id.get(identifier)
            pdf = (document is not None and not document.is_folder
                   and safe_component(document.name) and document.name.lower().endswith('.pdf'))
            result.append({
                'id': identifier, 'present_in_export': document is not None,
                'is_pdf': bool(pdf), 'in_selected_subtree': identifier in self.scope_ids,
                'status': ('NOT_PRESENT_IN_EXPORT' if document is None else
                           'PRESENT_NON_PDF_OR_INVALID_NAME' if not pdf else
                           'PRESENT_PDF_IN_SCOPE' if identifier in self.scope_ids else
                           'PRESENT_PDF_OUTSIDE_SCOPE'),
            })
        return result


def import_gateway_candidates(config) -> dict:
    if config.command != 'fill-urls' or config.gateway_json is None:
        raise ValidationError('Нужен fill-urls с явным gateway_json.')
    raw = read_snapshot(config.gateway_json, config.max_gateway_bytes)
    gateway_hash = hashlib.sha256(raw).hexdigest()
    try:
        documents = parse_gateway_search_documents(raw, max_response_bytes=config.max_gateway_bytes)
    except ApiError as exc:
        raise ValidationError('GATEWAY_IMPORT_REJECTED: ' + exc.code.value) from None
    rules = FolderRules(config.target_folder_id, config.office_folders,
                        config.contractor_folders, config.inspection_folder)
    registry = audit_registry(config)
    inspections = InspectionIndex([registry], {config.inspection_type: rules})
    if any(isinstance(c['number'], str) and config.filename_separator in c['number']
           for c in inspections.candidates):
        raise ValidationError('Разделитель встречается внутри номера реестра; нужно явное правило.')
    index = GatewaySearchIndex(documents, config.inspection_type, int(config.target_folder_id),
                               config.filename_separator, config.filename_numbers)
    rows = []
    for candidate in inspections.candidates:
        row = {k: candidate[k] for k in ('sheet', 'row', 'registry_type', 'id', 'number')}
        row.update({'status': None, 'folder_id': None, 'folder_group': None,
                    'candidate_group': None, 'selected_document_id': None})
        if candidate['existing_url']:
            row['status'] = 'EXISTING_URL'
        elif candidate['reasons'] or config.inspection_type in inspections.blocked_types:
            row['status'] = 'INVALID_REGISTRY_DATA'
        else:
            category, _ = inspections.lookup(config.inspection_type, candidate['number'])
            if category == 'AMBIGUOUS':
                row['status'] = 'AMBIGUOUS_REGISTRY'
            else:
                folder, problem = index.folder(candidate['proposed_folder']['components'])
                row['folder_id'], row['folder_group'] = folder, problem
                if problem is not None:
                    row['status'] = index.folder_groups[problem]['status']
                else:
                    group_id = index.lookup(config.inspection_type, folder, candidate['number'])
                    row['candidate_group'] = group_id
                    row['status'] = ('NOT_FOUND_IN_EXPORT' if group_id is None else
                                     'AMBIGUOUS_DOCUMENT' if
                                     index.document_groups[group_id]['ambiguous'] else
                                     'CANDIDATE_UNVERIFIED')
        rows.append(row)
    if (hashlib.sha256(read_snapshot(config.gateway_json, config.max_gateway_bytes)).hexdigest()
            != gateway_hash or hashlib.sha256(read_snapshot(config.excel, config.max_file_bytes))
            .hexdigest() != registry['sha256']):
        raise ValidationError('INPUT_CHANGED: Excel или Gateway JSON изменился во время анализа.')
    counts = dict(Counter(row['status'] for row in rows))
    known = index.known_documents()
    return {
        'schema_version': 1, 'command': 'fill-urls', 'mode': 'LOCAL_GATEWAY_JSON',
        'dry_run': True, 'network_enabled': False, 'write_enabled': False,
        'source_write_enabled': False, 'excel_written': False, 'journal_updated': False,
        'status': 'CANDIDATES_ONLY',
        'matching_policy': {'exact_number': True, 'direct_children_only': True,
                            'unicode_normalization_for_matching': False,
                            'scope_and_registry_type_source': 'LOCAL_CONFIGURATION',
                            'automatic_selection': False, 'url_relationship_verified': False},
        'source': {'excel_sha256': registry['sha256'], 'gateway_sha256': gateway_hash,
                   'gateway_bytes': len(raw), 'registry_type': config.inspection_type,
                   'root_folder_id': index.root_id},
        'known_documents': known,
        'coverage': {
            'server_completeness_verified': False, 'pagination_verified': False,
            'snapshot_freshness_verified': False, 'registry_scope_verified': False,
            'documents_in_export': len(documents.documents),
            'descendants_in_scope': len(index.scope_ids), 'pdfs_in_scope': index.pdf_count,
            'unparsed_pdf_names': index.invalid_pdf_count,
            'root_record_present': index.root_id in index.by_id,
            'missing_ancestor_records': len(index.missing_ancestor_ids),
            'known_pdf_ids_all_present': all(item['is_pdf'] for item in known),
            'known_pdf_ids_all_in_scope': all(item['is_pdf'] and item['in_selected_subtree']
                                             for item in known),
            'absence_proves_no_document': False,
        },
        'summary': counts, 'rows': rows, 'candidate_groups': index.document_groups,
        'folder_groups': index.folder_groups, 'gateway_issues': index.issues,
        'registry_status': registry['status'], 'registry_issues': registry['issues'],
        'metrics': {'rows_indexed': inspections.rows_indexed,
                    'documents_indexed': len(documents.documents),
                    'folder_lookups': index.folder_lookups, 'number_lookups': index.number_lookups},
    }
