"""Explicit paths and a shared, exact Gateway hierarchy index. Never creates folders."""

import re
import unicodedata
from collections import defaultdict
from dataclasses import dataclass

from sarex_loader.safety import ValidationError


def safe_component(value: object) -> bool:
    if not isinstance(value, str) or not value or len(value) > 250:
        return False
    if value != value.strip() or value.endswith('.') or value in {'.', '..'}:
        return False
    if any(c in '<>:"/\\|?*∕⁄／＼' or unicodedata.category(c).startswith('C')
           or (c.isspace() and c != ' ') for c in value):
        return False
    if len(value.encode('utf-8')) > 255:
        return False
    return not re.fullmatch(r'(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?', value)


def collision_key(value: str) -> str:
    """Diagnostic only: never use this key to select an inspection or a folder."""
    return unicodedata.normalize('NFKC', value).casefold()


MONTHS = ('январь', 'февраль', 'март', 'апрель', 'май', 'июнь',
          'июль', 'август', 'сентябрь', 'октябрь', 'ноябрь', 'декабрь')


def calendar_month(name):
    """Recognize only a single explicit month AND year; never infer a missing year."""
    if re.fullmatch(r'[0-9]{4}-(0[1-9]|1[0-2])', name):
        return name
    match = re.fullmatch(r'(?:[0-9]+\.\s*)?(' + '|'.join(MONTHS)
                         + r')\s+([0-9]{4})', name.casefold())
    if match:
        return f'{match[2]}-{MONTHS.index(match[1]) + 1:02d}'
    return None


def tree_component(value):
    """Remote names are inert metadata, NOT filesystem components (may contain /)."""
    return (type(value) is str and 0 < len(value) <= 250 and value == value.strip()
            and value not in {'.', '..'}
            and not any(unicodedata.category(c).startswith('C') for c in value))


def _aliases(mapping):
    if (type(mapping) is not dict or not mapping or any(
            not tree_component(k) or not tree_component(v) or '{' in v or '}' in v
            for k, v in mapping.items())):
        raise ValidationError('ROUTING_ALIASES_INVALID')
    # Many source spellings may explicitly denote one destination. No fuzzy matching.
    return dict(mapping)


def validate_mapping(mapping: object) -> dict[str, str]:
    if not isinstance(mapping, dict) or not mapping:
        raise ValidationError('Нужна непустая явная карта названий папок.')
    seen = set()
    for source, target in mapping.items():
        if not isinstance(source, str) or not source or not safe_component(target):
            raise ValidationError('Недопустимый ключ или компонент карты папок.')
        key = collision_key(target)
        if key in seen:
            raise ValidationError('Коллизия назначений в карте папок; требуется ручное решение.')
        seen.add(key)
    return dict(mapping)


@dataclass(frozen=True)
class FolderRules:
    root_id: str
    offices: dict[str, str]
    contractors: dict[str, str]
    inspection_folder: str
    prefix: tuple[str, ...] = ()
    layouts: tuple[dict, ...] = ()

    def __post_init__(self):
        if not isinstance(self.root_id, str) or not re.fullmatch(r'[1-9][0-9]{0,18}', self.root_id):
            raise ValidationError('Нужен явный ID корневой папки.')
        if type(self.layouts) not in (list, tuple) or len(self.layouts) > 500:
            raise ValidationError('ROUTING_LAYOUTS_INVALID')
        if self.layouts:
            self._validate_layouts()
            return
        if not safe_component(self.inspection_folder):
            raise ValidationError('Нужен безопасный явный компонент папки инспекций.')
        object.__setattr__(self, 'offices', validate_mapping(self.offices))
        object.__setattr__(self, 'contractors', validate_mapping(self.contractors))
        if (type(self.prefix) is not tuple or len(self.prefix) > 16
                or any(not safe_component(p) for p in self.prefix)):
            raise ValidationError('Нужен явный безопасный префикс иерархии.')

    def _validate_layouts(self):
        if self.prefix:
            raise ValidationError('ROUTING_LAYOUTS_INVALID')
        object.__setattr__(self, 'offices', _aliases(self.offices))
        object.__setattr__(self, 'contractors', _aliases(self.contractors))
        layouts = []
        for layout in self.layouts:
            if (type(layout) is not dict
                    or not {'office', 'contractor', 'components'} <= layout.keys()
                    or layout.keys() - {'office', 'contractor', 'components', 'months'}
                    or layout['office'] not in self.offices.values()
                    or layout['contractor'] not in self.contractors.values()):
                raise ValidationError('ROUTING_LAYOUTS_INVALID')
            months = layout.get('months')
            if 'months' in layout and (
                    type(months) not in (list, tuple) or not 1 <= len(months) <= 120
                    or any(type(m) is not str or re.fullmatch(
                        r'[0-9]{4}-(0[1-9]|1[0-2])', m) is None for m in months)
                    or len(set(months)) != len(months)):
                raise ValidationError('ROUTING_LAYOUTS_INVALID')
            parts = layout['components']
            if (type(parts) not in (list, tuple) or not 1 <= len(parts) <= 32
                    or parts.count('{month}') != 1 or any(
                        not tree_component(p) or (('{' in p or '}' in p)
                        and p not in {'{office}', '{contractor}', '{month}'}) for p in parts)):
                raise ValidationError('ROUTING_LAYOUTS_INVALID')
            validated = {**layout, 'components': tuple(parts)}
            if months is not None:
                validated['months'] = tuple(months)
            layouts.append(validated)
        object.__setattr__(self, 'layouts', tuple(layouts))

    def propose(self, record: dict) -> tuple[dict | None, str | None]:
        office, contractor, month = (record.get(k) for k in ('office', 'contractor', 'month'))
        if not isinstance(office, str) or office not in self.offices:
            return None, 'OFFICE_MAPPING_MISSING'
        if not isinstance(contractor, str) or contractor not in self.contractors:
            return None, 'CONTRACTOR_MAPPING_MISSING'
        if not isinstance(month, str) or not re.fullmatch(r'[0-9]{4}-(0[1-9]|1[0-2])', month):
            return None, 'INVALID_MONTH'
        if self.layouts:
            layouts = [r for r in self.layouts if r['office'] == self.offices[office]
                       and r['contractor'] == self.contractors[contractor]
                       and ('months' not in r or month in r['months'])]
            if len(layouts) != 1:
                return None, 'AMBIGUOUS_ROUTE' if layouts else 'ROUTE_NOT_CONFIGURED'
            values = {'{office}': self.offices[office],
                      '{contractor}': self.contractors[contractor],
                      '{month}': '{month:' + month + '}'}
            return {'root_id': self.root_id,
                    'components': [values.get(p, p) for p in layouts[0]['components']],
                    'verified_in_sarex': False}, None
        return {
            'root_id': self.root_id,
            'components': [*self.prefix, self.offices[office], self.contractors[contractor],
                           self.inspection_folder, month],
            'verified_in_sarex': False,
        }, None


@dataclass(frozen=True)
class FolderResolution:
    folder_id: int | None
    status: str
    path_ids: tuple[int, ...] = ()


class FolderResolver:
    """One index for upload and recovery; O(path length) lookup, no row-level IO.

    RESOLVED_IN_SNAPSHOT is evidence of an exact path in the selected responses,
    not proof of server completeness or authorization to write.
    """

    def __init__(self):
        self.documents = {}
        self.parents = {}
        self.ancestor_ids = set()
        self.children = defaultdict(dict)
        self.names = defaultdict(set)
        self.months = defaultdict(set)
        self.queried_folders = set()
        self.metadata = []
        self.source_hashes = []
        self.overlap = 0
        self.lookups = 0
        self.network_enabled = False
        self.observation = None

    def add(self, documents):
        for d in documents:
            previous = self.documents.get(d.id)
            if previous is not None:
                if previous != d:
                    raise ValidationError('TREE_CONFLICT: данные одного ID изменились.')
                self.overlap += 1
                continue
            for pos, identifier in enumerate(d.path_ids):
                parent = d.path_ids[pos - 1] if pos else None
                if identifier in self.parents and self.parents[identifier] != parent:
                    raise ValidationError('TREE_CONFLICT: несовместимая иерархия.')
                self.parents[identifier] = parent
            self.documents[d.id] = d
            if not d.is_folder and d.id in self.ancestor_ids:
                raise ValidationError('TREE_CONFLICT: файл указан родителем.')
            self.ancestor_ids.update(d.path_ids[:-1])
            if len(self.documents) > 100_000:
                raise ValidationError('TREE_LIMIT: слишком много объектов.')
            if len(d.path_ids) > 1:
                parent = d.path_ids[-2]
                if parent in self.documents and not self.documents[parent].is_folder:
                    raise ValidationError('TREE_CONFLICT: файл указан родителем.')
                self.children[parent][d.id] = d
                if d.is_folder:
                    self.names[(parent, collision_key(d.name))].add(d.id)
                    month = calendar_month(d.name)
                    if month is not None:
                        self.months[(parent, month)].add(d.id)
        # Also reject files that occur only as intermediate ancestors.
        for d in documents:
            if any(i in self.documents and not self.documents[i].is_folder
                   for i in d.path_ids[:-1]):
                raise ValidationError('TREE_CONFLICT: файл указан предком.')

    def child(self, parent_id, name):
        self.lookups += 1
        month = re.fullmatch(r'\{month:([0-9]{4}-(?:0[1-9]|1[0-2]))\}', name)
        if month:
            ids = self.months.get((parent_id, month[1]), ())
            if len(ids) > 1:
                return FolderResolution(None, 'AMBIGUOUS_FOLDER')
            if len(ids) == 1:
                d = self.documents[next(iter(ids))]
                if len(self.names[(parent_id, collision_key(d.name))]) > 1:
                    return FolderResolution(None, 'AMBIGUOUS_FOLDER')
                return FolderResolution(d.id, 'RESOLVED_IN_SNAPSHOT', d.path_ids)
            return FolderResolution(None, 'FOLDER_NOT_RESOLVED_IN_SNAPSHOT')
        ids = self.names.get((parent_id, collision_key(name)), ())
        if len(ids) > 1:
            return FolderResolution(None, 'AMBIGUOUS_FOLDER')
        if len(ids) == 1:
            d = self.documents[next(iter(ids))]
            if d.name == name:
                return FolderResolution(d.id, 'RESOLVED_IN_SNAPSHOT', d.path_ids)
        return FolderResolution(None, 'FOLDER_NOT_RESOLVED_IN_SNAPSHOT')

    def resolve(self, root_id, components):
        from sarex_loader.api_models import valid_id

        if (not valid_id(root_id) or not isinstance(components, (tuple, list))
                or len(components) > 32 or any(not tree_component(p) for p in components)):
            raise ValidationError('TREE_PATH_INVALID')
        root = self.documents.get(root_id)
        if root is None or not root.is_folder:
            return FolderResolution(None, 'ROOT_NOT_RESOLVED_IN_SNAPSHOT')
        result = FolderResolution(root_id, 'RESOLVED_IN_SNAPSHOT', root.path_ids)
        for component in components:
            result = self.child(result.folder_id, component)
            if result.folder_id is None:
                break
        return result
