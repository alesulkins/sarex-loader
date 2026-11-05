"""Explicit local configuration only. No environment or credential discovery."""

import os
import re
import stat
import tomllib
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath

from sarex_loader.safety import ValidationError, require_offline_dry_run

MAX_CONFIG_BYTES = 65536
COMMANDS = ("audit", "match", "upload", "fill-urls")
INSPECTION_TYPES = ("sk", "vk", "geodetic")
CONFIG_KEYS = frozenset(
    {
        "input_root", "excel", "pdf_dir", "inspection_type", "target_folder_id",
        "dry_run", "network_enabled", "write_enabled", "output_dir", "max_file_bytes",
        "filename_separator", "office_folders", "contractor_folders", "inspection_folder",
        "filename_numbers", "journal_dir", "gateway_json", "max_gateway_bytes",
        "tree", "folder_prefix", "folder_routes",
    }
)


def local_path(value: str | Path) -> Path:
    """Reject remote paths, traversal and control characters without echoing input."""
    if not isinstance(value, (str, Path)):
        raise ValidationError("Путь должен быть непустой строкой.")
    text = str(value)
    if os.name == 'nt':
        validate_windows_path(text)
        return Path(text)
    if (
        not text.strip()
        or text.startswith(("//", "~"))
        or ":" in text
        or "\\" in text
        or any(unicodedata.category(char) in {"Cc", "Cf"} for char in text)
        or ".." in Path(text).parts
    ):
        raise ValidationError("Недопустимый локальный путь: проверьте формат и компоненты.")
    return Path(text)


def validate_windows_path(text):
    path = PureWindowsPath(text)
    parts = path.parts[1:] if path.drive else path.parts
    reserved = re.compile(r'(?i)^(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)')
    if (not text.strip() or text.startswith(('~', '\\\\', '//'))
            or path.drive and (not re.fullmatch('[A-Za-z]:', path.drive) or not path.root)
            or path.root and not path.drive or any(reserved.match(p) for p in parts)
            or any(part in ('.', '..') or part.endswith((' ', '.'))
                   or any(c in part for c in ':*?<>|"') for part in parts)
            or any(unicodedata.category(c) in {'Cc', 'Cf'} for c in text)):
        raise ValidationError('Нужен локальный путь Windows: без UNC, ссылок, потоков ADS и ..')


def checked_path(path: Path, *, directory: bool) -> Path:
    """Inspect metadata only; reject links in every component, including parents."""
    path = path.absolute()
    try:
        for component in (*reversed(path.parents), path):
            info = component.lstat()
            mode = info.st_mode
            if os.name == 'nt':
                from sarex_loader.windows_files import unsafe_link

                if unsafe_link(info):
                    raise ValidationError('Ссылки и junction в путях не разрешены.')
            if stat.S_ISLNK(mode) or (
                hasattr(component, "is_junction") and component.is_junction()
            ):
                raise ValidationError("Симлинки и junction в путях не разрешены.")
        valid = stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)
        if not valid:
            raise ValidationError("Ожидается обычный файл или каталог соответствующего типа.")
        return path.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        if isinstance(exc, ValidationError):
            raise
        raise ValidationError("Локальный путь отсутствует или недоступен.") from None


def within_root(value: str | Path, root: Path, *, directory: bool) -> Path:
    candidate = local_path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    # Check containment before metadata access outside the explicitly selected root.
    if not candidate.is_relative_to(root):
        raise ValidationError("Входной путь должен находиться внутри input_root.")
    candidate = checked_path(candidate, directory=directory)
    if not candidate.is_relative_to(root):
        raise ValidationError("Входной путь выходит за пределы input_root.")
    return candidate


@dataclass(frozen=True)
class RunConfig:
    command: str
    input_root: str | Path = field(repr=False)
    excel: str | Path = field(repr=False)
    inspection_type: str
    pdf_dir: str | Path | None = field(default=None, repr=False)
    target_folder_id: str | None = field(default=None, repr=False)
    dry_run: bool = True
    network_enabled: bool = False
    write_enabled: bool = False
    output_dir: str | Path | None = field(default=None, repr=False)
    max_file_bytes: int = 16 * 1024 * 1024
    filename_separator: str | None = field(default=None, repr=False)
    office_folders: dict[str, str] | None = field(default=None, repr=False)
    contractor_folders: dict[str, str] | None = field(default=None, repr=False)
    inspection_folder: str | None = field(default=None, repr=False)
    filename_numbers: dict[str, str] | None = field(default=None, repr=False)
    journal_dir: str | Path | None = field(default=None, repr=False)
    gateway_json: str | Path | None = field(default=None, repr=False)
    max_gateway_bytes: int = 1024**2
    tree: dict | None = field(default=None, repr=False)
    folder_prefix: tuple[str, ...] = ()
    folder_routes: tuple[dict, ...] = ()

    def __post_init__(self) -> None:
        if type(self.folder_routes) not in (tuple, list) or len(self.folder_routes) > 500:
            raise ValidationError('ROUTING_LAYOUTS_INVALID')
        if isinstance(self.folder_prefix, list):
            object.__setattr__(self, 'folder_prefix', tuple(self.folder_prefix))
        if self.tree is not None and self.command != 'upload':
            raise ValidationError('tree в RunConfig разрешён только для upload.')
        if self.folder_prefix and self.tree is None:
            raise ValidationError('folder_prefix требует общий tree resolver.')
        if self.folder_routes and self.tree is None:
            raise ValidationError('folder_routes требует общий tree resolver.')
        require_offline_dry_run(
            dry_run=self.dry_run,
            network_enabled=self.network_enabled,
            write_enabled=self.write_enabled,
        )
        if self.command not in COMMANDS or self.inspection_type not in INSPECTION_TYPES:
            raise ValidationError("Нужны известная команда и inspection_type: sk, vk или geodetic.")
        if self.target_folder_id is not None and (
            not isinstance(self.target_folder_id, str)
            or re.fullmatch(r"[1-9][0-9]{0,18}", self.target_folder_id) is None
        ):
            raise ValidationError("target_folder_id должен быть строкой с положительным целым ID.")
        if self.command != "audit" and self.target_folder_id is None:
            raise ValidationError("Для match, upload и fill-urls нужен явный target_folder_id.")
        if self.command in {"upload", "match"} and self.pdf_dir is None:
            raise ValidationError("Для upload и match нужен явный pdf_dir.")
        if (type(self.max_gateway_bytes) is not int
                or not 1 <= self.max_gateway_bytes <= 8 * 1024**2):
            raise ValidationError('Лимит Gateway JSON должен быть целым от 1 до 8388608.')
        if self.gateway_json is not None:
            if self.command != 'fill-urls':
                raise ValidationError('gateway_json разрешён только для fill-urls.')
            from sarex_loader.matching import validate_separator

            validate_separator(self.filename_separator)
        elif self.max_gateway_bytes != 1024**2:
            raise ValidationError('Для лимита Gateway нужен явный gateway_json.')
        has_rules = any(value is not None for value in (
            self.filename_separator, self.office_folders, self.contractor_folders,
            self.inspection_folder, self.filename_numbers))
        if self.command == "match" or self.command in {"upload", "fill-urls"} and has_rules:
            from sarex_loader.folder_resolver import FolderRules
            from sarex_loader.matching import validate_filename_numbers, validate_separator

            if self.command != 'fill-urls':
                validate_separator(self.filename_separator)
            object.__setattr__(self, 'filename_numbers',
                               validate_filename_numbers(self.filename_numbers))
            rules = FolderRules(self.target_folder_id, self.office_folders,
                                self.contractor_folders, self.inspection_folder, self.folder_prefix,
                                self.folder_routes)
            object.__setattr__(self, 'office_folders', rules.offices)
            object.__setattr__(self, 'contractor_folders', rules.contractors)
            object.__setattr__(self, 'folder_routes', rules.layouts)
        elif has_rules:
            raise ValidationError('Правила сопоставления не разрешены для audit.')
        if type(self.max_file_bytes) is not int or not 1 <= self.max_file_bytes <= 64 * 1024**2:
            raise ValidationError("max_file_bytes должен быть целым числом от 1 до 67108864.")
        root = checked_path(local_path(self.input_root), directory=True)
        if root == Path(root.anchor):
            raise ValidationError("Нельзя выбирать корень файловой системы как input_root.")
        excel = within_root(self.excel, root, directory=False)
        if excel.suffix.lower() != ".xlsx" or excel.name.startswith("~$"):
            raise ValidationError("Нужен обычный файл .xlsx, не временный файл Excel.")
        object.__setattr__(self, "input_root", root)
        object.__setattr__(self, "excel", excel)
        if self.tree is not None:
            from sarex_loader.tree_source import TreeSource, parse_tree_source

            if type(self.tree) is not TreeSource:
                object.__setattr__(self, 'tree', parse_tree_source(self.tree, root))
        if self.gateway_json is not None:
            gateway = within_root(self.gateway_json, root, directory=False)
            if gateway.suffix.lower() != '.json':
                raise ValidationError('Нужен локальный .json ответ Gateway, не HAR.')
            object.__setattr__(self, 'gateway_json', gateway)
        if self.pdf_dir is not None:
            object.__setattr__(self, "pdf_dir", within_root(self.pdf_dir, root, directory=True))
        if self.output_dir is not None:
            output = local_path(self.output_dir).absolute()
            checked_path(output.parent, directory=True)
            if output.is_relative_to(root) or root.is_relative_to(output):
                raise ValidationError("Выходной каталог должен быть отдельно от input_root.")
            if output.exists() or output.is_symlink():
                raise ValidationError("Выходной каталог уже существует; перезапись запрещена.")
            object.__setattr__(self, "output_dir", output)
        if self.journal_dir is not None:
            if self.command not in {'upload', 'fill-urls'}:
                raise ValidationError('journal_dir разрешён только для локального конвейера.')
            journal = local_path(self.journal_dir).absolute()
            checked_path(journal.parent, directory=True)
            if journal.is_relative_to(root) or root.is_relative_to(journal):
                raise ValidationError('Журнал должен находиться отдельно от входных файлов.')
            if self.output_dir is not None and (
                journal.is_relative_to(self.output_dir) or self.output_dir.is_relative_to(journal)
            ):
                raise ValidationError('Каталоги отчётов и журнала должны быть раздельными.')
            object.__setattr__(self, 'journal_dir', journal)


def load_config(
    command: str, overrides: dict[str, object], config_path: str | None = None
) -> RunConfig:
    values: dict[str, object] = {}
    if config_path is not None:
        path = checked_path(local_path(config_path), directory=False)
        if path.suffix.lower() != ".toml":
            raise ValidationError("Конфигурация должна быть файлом .toml.")
        try:
            from sarex_loader.file_safety import read_snapshot

            raw = read_snapshot(path, MAX_CONFIG_BYTES)
            values = tomllib.loads(raw.decode("utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError):
            raise ValidationError("Не удалось прочитать корректную TOML-конфигурацию.") from None
        # Reject unsafe source values before CLI overrides, even --dry-run.
        require_offline_dry_run(
            dry_run=values.get("dry_run", True),
            network_enabled=values.get("network_enabled", False),
            write_enabled=values.get("write_enabled", False),
        )
        if "input_root" in values:
            root = local_path(values["input_root"])
            values["input_root"] = root if root.is_absolute() else path.parent / root
        for key in ('output_dir', 'journal_dir'):
            if key in values:
                output = local_path(values[key])
                values[key] = output if output.is_absolute() else path.parent / output
    if (values.keys() | overrides.keys()) - CONFIG_KEYS:
        raise ValidationError("Неизвестные поля конфигурации запрещены; секреты не принимаются.")
    values.update(overrides)
    if not {"input_root", "excel", "inspection_type"} <= values.keys():
        raise ValidationError("Нужны input_root, excel и inspection_type.")
    return RunConfig(command=command, **values)
