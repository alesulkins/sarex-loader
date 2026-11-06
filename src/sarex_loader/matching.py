"""Expected linear-time exact matching, with shared candidate and collision tables."""

import re
from collections import Counter, defaultdict
from datetime import date

from sarex_loader.folder_resolver import FolderRules, collision_key, safe_component
from sarex_loader.pdf_route_guard import filename_route_checks
from sarex_loader.pdf_scan import scan_pdfs
from sarex_loader.safety import ValidationError

CATEGORIES = ('MATCHED', 'NOT_FOUND', 'AMBIGUOUS', 'INVALID_FILENAME', 'INVALID_REGISTRY_DATA')


def validate_separator(separator: object) -> str:
    # Literal delimiter, not a user-supplied regex: no backtracking or implicit grammar.
    if not isinstance(separator, str) or not 1 <= len(separator) <= 32:
        raise ValidationError('Нужен явный filename_separator длиной от 1 до 32 символов.')
    if not safe_component('x' + separator + 'x'):
        raise ValidationError('Недопустимый разделитель номера в имени PDF.')
    return separator


def extract_number(filename: str, separator: str) -> str | None:
    """Last literal delimiter + nonempty exact suffix immediately before .pdf.

    Only user-confirmed leading ASCII spaces before an all-digit suffix are ignored.
    No case folding, transliteration, slash substitution or numeric conversion.
    """
    validate_separator(separator)
    if not safe_component(filename) or not filename.lower().endswith('.pdf'):
        return None
    prefix, found, number = filename[:-4].rpartition(separator)
    if re.fullmatch(r' +[0-9]+', number):
        number = number.lstrip(' ')
    if not found or not prefix or not safe_component(number):
        return None
    return number


def validate_filename_numbers(values: object) -> dict[str, str]:
    """Explicit whole-filename evidence, scoped to the configured registry type."""
    if values is None:
        return {}
    if not isinstance(values, dict) or len(values) > 1000:
        raise ValidationError('Нужна ограниченная карта точных имён PDF и номеров.')
    seen = set()
    for filename, number in values.items():
        if (not safe_component(filename) or not filename.lower().endswith('.pdf')
                or not safe_component(number) or collision_key(filename) in seen):
            raise ValidationError('Небезопасное или неоднозначное явное соответствие PDF.')
        seen.add(collision_key(filename))
    return dict(values)


class InspectionIndex:
    """Build once in O(N + diagnostics); exact (registry_type, number) hash lookups.

    Store each candidate once. Never expand a large ambiguous bucket for every PDF.
    Inputs are in-process stage-2 results, not an independently loaded JSON report.
    """

    def __init__(self, registries: list[dict], routes: dict[str, FolderRules]):
        self.groups = []
        self.candidates = []
        self.by_key = {}
        self.blocked_types = set()
        self.registry_sources = []
        self.registry_types = set()
        self.lookups = 0
        self.rows_indexed = 0
        ids = defaultdict(list)
        normalized = defaultdict(list)
        for source_index, registry in enumerate(registries):
            kind = registry['registry_type']
            self.registry_types.add(kind)
            if kind not in routes:
                raise ValidationError('Нет явных правил папок для типа реестра.')
            self.registry_sources.append({k: registry[k] for k in
                                          ('file', 'registry_type', 'sha256', 'status', 'issues')})
            invalid = defaultdict(set)
            ambiguous = set()
            if registry['status'] == 'REJECTED':
                self.blocked_types.add(kind)
            for issue in registry['issues']:
                code = issue['code']
                if issue['severity'] != 'error':
                    continue
                locations = issue.get('locations') or [issue]
                for location in locations:
                    address = (location.get('sheet'), location.get('row'))
                    if code in {'DUPLICATE_NUMBER', 'DUPLICATE_FOLDER_NUMBER',
                                'DUPLICATE_EXACT_DATE_NUMBER', 'DUPLICATE_NORMALIZATION_COLLISION'}:
                        ambiguous.add(address)
                    elif address[1] is None or address[1] == 1:
                        self.blocked_types.add(kind)
                    else:
                        invalid[address].add(code)
            for record in registry['records']:
                self.rows_indexed += 1
                address = (record['sheet'], record['row'])
                reasons = set(invalid[address])
                number = record['number']
                if not record.get('id_key'):
                    reasons.add('INVALID_ID')
                if not isinstance(number, str) or not safe_component(number):
                    reasons.add('NUMBER_NOT_REPRESENTABLE_AS_EXACT_FILENAME_SUFFIX')
                proposal, error = routes[kind].propose(record)
                if error:
                    reasons.add(error)
                candidate = {
                    'source': source_index, 'sheet': record['sheet'], 'row': record['row'],
                    'registry_type': kind, 'id': record['id_key'], 'number': number,
                    'routing_root_id': routes[kind].root_id,
                    'office': record['office'], 'contractor': record['contractor'],
                    'date': record['date'], 'month': record['month'],
                    'url_class': record['url_class'],
                    'existing_url': record['url_class'] != 'EMPTY',
                    'proposed_folder': proposal, 'reasons': reasons,
                    'ambiguous': address in ambiguous,
                }
                candidate_id = len(self.candidates)
                self.candidates.append(candidate)
                if record['id_key']:
                    ids[(source_index, record['id_key'])].append(candidate_id)
                if isinstance(number, str) and number:
                    key = (kind, number)
                    if key not in self.by_key:
                        self.by_key[key] = len(self.groups)
                        self.groups.append({'registry_type': kind, 'number': number,
                                            'candidate_ids': []})
                        normalized[(kind, collision_key(number))].append(self.by_key[key])
                    self.groups[self.by_key[key]]['candidate_ids'].append(candidate_id)
        for members in ids.values():
            if len(members) > 1:
                for member in members:
                    self.candidates[member]['reasons'].add('DUPLICATE_ID')
        for members in normalized.values():
            if len(members) > 1:
                for member in members:
                    self.groups[member]['unicode_collision'] = True
        for candidate in self.candidates:
            candidate['reasons'] = sorted(candidate['reasons'])
            candidate['status'] = ('INVALID_REGISTRY_DATA' if candidate['reasons']
                                   else 'VALID_ROW')
        for group in self.groups:
            members = [self.candidates[i] for i in group['candidate_ids']]
            if len(members) > 1 or group.get('unicode_collision') or members[0]['ambiguous']:
                group['category'] = 'AMBIGUOUS'
            elif members[0]['reasons']:
                group['category'] = 'INVALID_REGISTRY_DATA'
            else:
                group['category'] = 'MATCHED'

    def lookup(self, kind: str, number: str) -> tuple[str, int | None]:
        self.lookups += 1
        group_id = self.by_key.get((kind, number))
        if kind in self.blocked_types or kind not in self.registry_types:
            return 'INVALID_REGISTRY_DATA', group_id
        if group_id is None:
            return 'NOT_FOUND', None
        return self.groups[group_id]['category'], group_id


def pdf_calendar_date(filename):
    """An exact, valid ISO date prefix; never infer dates from ambiguous names."""
    match = re.match(r'^(\d{4}-\d{2}-\d{2})(?:-|_)', filename)
    try:
        return date.fromisoformat(match[1]).isoformat() if match else None
    except ValueError:
        return None


def selected_candidates(index, group_id, filename):
    if group_id is None:
        return []
    group = index.groups[group_id]
    members = group['candidate_ids']
    day = pdf_calendar_date(filename)
    if len(members) <= 1 or not day or group.get('unicode_collision'):
        return members
    # A row with an unknown date cannot safely be excluded.
    try:
        days = [date.fromisoformat(index.candidates[i]['date'][:10]).isoformat()
                for i in members]
    except (TypeError, ValueError):
        return members
    exact = [i for i, value in zip(members, days, strict=True) if value == day]
    return exact if len(exact) == 1 else members


def build_match_report(index: InspectionIndex, entries, kind: str, separator: str,
                       filename_numbers: dict[str, str] | None = None) -> dict:
    validate_separator(separator)
    explicit = validate_filename_numbers(filename_numbers)
    # Otherwise a real number like 12-34 could silently become the different number 34.
    # Reject the rule before scanning; choosing a different literal boundary is explicit.
    if any(c['registry_type'] == kind and isinstance(c['number'], str)
           and separator in c['number'] for c in index.candidates):
        raise ValidationError(
            'Разделитель встречается внутри номера реестра; выберите другое явное правило.'
        )
    files = []
    duplicates = []
    buckets = {name: defaultdict(list) for name in ('number', 'sha256', 'inode', 'unicode_name')}
    for entry in entries:
        extracted = extract_number(entry['filename'], separator)
        number = (explicit[entry['filename']] if entry['filename'] in explicit
                  else extracted)
        reason = entry['reason'] or (None if number is not None else 'SUFFIX_RULE_MISMATCH')
        category, group = ('INVALID_FILENAME', None) if reason else index.lookup(kind, number)
        members = selected_candidates(index, group, entry['filename'])
        if (category == 'AMBIGUOUS' and len(members) == 1
                and len(index.groups[group]['candidate_ids']) > 1):
            category = ('INVALID_REGISTRY_DATA' if index.candidates[members[0]]['reasons']
                        else 'MATCHED')
        item = {**entry, 'registry_type': kind, 'number': number, 'category': category,
                'candidate_group': group, 'duplicate_groups': [],
                'reasons': [reason] if reason else [], 'proposed_path': None}
        if group is not None and members is not index.groups[group]['candidate_ids']:
            item['selected_candidate_ids'] = list(members)
        if entry['filename'] in explicit:
            item['number_evidence'] = 'EXPLICIT_FILENAME_MAPPING'
            item['extracted_number'] = extracted
            if extracted != number and (kind, extracted) in index.by_key:
                item['category'] = 'AMBIGUOUS'
                item['reasons'].append('EXPLICIT_NUMBER_CONFLICT')
        file_id = len(files)
        files.append(item)
        buckets['unicode_name'][collision_key(entry['filename'])].append(file_id)
        if number is not None:
            buckets['number'][(kind, number)].append(file_id)
        if entry['sha256']:
            buckets['sha256'][entry['sha256']].append(file_id)
        if entry['identity']:
            buckets['inode'][tuple(entry['identity'][:2])].append(file_id)
    for basis, groups in buckets.items():
        for members in groups.values():
            if basis == 'number' and all(pdf_calendar_date(files[i]['filename'])
                                         for i in members):
                dated = defaultdict(list)
                for i in members:
                    dated[pdf_calendar_date(files[i]['filename'])].append(i)
                # Different days are distinct inspections; identical days still block.
                members_sets = list(dated.values())
            else:
                members_sets = [members]
            for subset in members_sets:
                if len(subset) > 1:
                    duplicates.append({'basis': basis, 'file_ids': subset})
    for group_id, duplicate in enumerate(duplicates):
        basis, members = duplicate['basis'], duplicate['file_ids']
        if len(members) < 2:
            continue
        for member in members:
            item = files[member]
            item['duplicate_groups'].append(group_id)
            if item['category'] != 'INVALID_FILENAME':
                item['category'] = 'AMBIGUOUS'
            item['reasons'].append('DUPLICATE_' + basis.upper())
    # Finalize only after the whole single pass: a later duplicate blocks earlier files too.
    for item in files:
        members = item.get('selected_candidate_ids')
        if members is None:
            members = (index.groups[item['candidate_group']]['candidate_ids']
                       if item['candidate_group'] is not None else [])
        item['filename_route_checks'] = [
            check for identifier in members
            for check in filename_route_checks(item['filename'], index.candidates[identifier],
                                               index.candidates[identifier]['routing_root_id'])]
        if item['filename_route_checks']:
            item['reasons'] += [c['code'] for c in item['filename_route_checks']]
            if item['category'] == 'MATCHED':
                item['category'] = 'INVALID_REGISTRY_DATA'
        if item['category'] == 'MATCHED':
            candidate = index.candidates[members[0]]
            folder = candidate['proposed_folder']
            item['proposed_path'] = {**folder,
                                     'components': [*folder['components'], item['filename']]}
            if candidate['existing_url']:
                item['reasons'].append('EXISTING_URL_REQUIRES_REVIEW')
        elif not item['reasons']:
            item['reasons'].append('REGISTRY_' + item['category'])
    counts = Counter(item['category'] for item in files)
    return {
        'schema_version': 1, 'stage': 3, 'dry_run': True, 'network_enabled': False,
        'write_enabled': False, 'source_write_enabled': False, 'upload_authorized': False,
        'filename_rule': {'separator': separator, 'position': 'last_literal_suffix',
                          'confirmed_on_customer_pdfs': False, 'transformations': [],
                          'explicit_filename_numbers': explicit},
        'registry_sources': index.registry_sources,
        'blocked_registry_types': sorted(index.blocked_types),
        'candidates': index.candidates, 'candidate_groups': index.groups,
        'files': files, 'duplicate_groups': duplicates,
        'summary': {category: counts[category] for category in CATEGORIES},
        'invalid_registry_rows': sum(bool(c['reasons']) for c in index.candidates),
        'metrics': {'rows_indexed': index.rows_indexed, 'entries_scanned': len(files),
                    'hash_lookups': index.lookups},
    }


def match_local(config) -> dict:
    from sarex_loader.audit import audit_registry

    rules = FolderRules(config.target_folder_id, config.office_folders,
                        config.contractor_folders, config.inspection_folder)
    index = InspectionIndex([audit_registry(config)], {config.inspection_type: rules})
    report = build_match_report(index, scan_pdfs(config.pdf_dir), config.inspection_type,
                                config.filename_separator, config.filename_numbers)
    report['pdf_directory'] = str(config.pdf_dir)
    return report
