"""Bounded OOXML preflight and read-only workbook access; never execute external content."""

import io
import posixpath
import re
import warnings
from pathlib import PurePosixPath
from xml.etree import ElementTree as ET
from xml.parsers import expat
from zipfile import BadZipFile, ZipFile

from openpyxl import load_workbook
from openpyxl.utils.cell import coordinate_to_tuple

from sarex_loader.safety import ValidationError

NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
MAX_EXPANDED = 64 * 1024**2
MAX_MEMBER = 32 * 1024**2
MAX_MEMBERS = 256
MAX_ROWS = 50000
MAX_COLS = 64
MAX_GRID = 1000000


class WorkbookRejected(ValidationError):
    def __init__(self, code: str):
        self.code = code
        super().__init__("Книга отклонена проверкой безопасности или структуры.")


def safe_xml(data: bytes):
    # Expat catches DTD also in UTF-16, where a byte substring check would fail.
    parser = expat.ParserCreate()
    depth = count = 0

    def forbidden(*args):
        raise WorkbookRejected("XML_DTD_OR_ENTITY")

    def start(name, attrs):
        nonlocal depth, count
        depth += 1
        count += 1
        if depth > 64 or count > 1000000:
            raise WorkbookRejected("XML_LIMIT")

    def end(name):
        nonlocal depth
        depth -= 1

    parser.StartDoctypeDeclHandler = forbidden
    parser.EntityDeclHandler = forbidden
    parser.ExternalEntityRefHandler = forbidden
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.Parse(data, True)
    return ET.fromstring(data)  # noqa: S314


def preflight(data: bytes) -> list[dict]:
    """Read every ZIP member without extraction; inspect actual cell coordinates."""
    try:
        with ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_MEMBERS or sum(x.file_size for x in infos) > MAX_EXPANDED:
                raise WorkbookRejected("ZIP_LIMIT")
            names = [x.filename for x in infos]
            if len(set(names)) != len(names):
                raise WorkbookRejected("ZIP_DUPLICATE_MEMBER")
            roots = {}
            for info in infos:
                name = info.filename
                parts = PurePosixPath(name).parts
                if name.startswith("/") or "\\" in name or ".." in parts or ":" in name:
                    raise WorkbookRejected("ZIP_UNSAFE_PATH")
                if info.flag_bits & 1 or info.file_size > MAX_MEMBER:
                    raise WorkbookRejected("ZIP_LIMIT")
                if info.file_size > max(info.compress_size, 1) * 200:
                    raise WorkbookRejected("ZIP_RATIO")
                lower = name.lower()
                if any(x in lower for x in (
                    "vbaproject", "externallinks/", "connections", "querytables/",
                    "activex/", "embeddings/", "macrosheets/", "dialogsheet", "customui/",
                )):
                    raise WorkbookRejected("ACTIVE_CONTENT_OR_CONNECTION")
                with archive.open(info) as member:
                    raw = member.read(MAX_MEMBER + 1)
                if len(raw) > MAX_MEMBER or len(raw) != info.file_size:
                    raise WorkbookRejected("ZIP_LIMIT")
                if lower.endswith((".xml", ".rels")):
                    root = safe_xml(raw)
                    roots[name] = root
                    for element in root.iter():
                        if element.tag.rsplit("}", 1)[-1] in {
                            "externalReferences", "externalReference", "connections", "queryTable",
                        }:
                            raise WorkbookRejected("ACTIVE_CONTENT_OR_CONNECTION")
                        content_type = element.get("ContentType", "").lower()
                        if any(x in content_type for x in ("macroenabled", "vba", "macrosheet")):
                            raise WorkbookRejected("ACTIVE_CONTENT_OR_CONNECTION")
                        if element.get("TargetMode", "").lower() == "external":
                            if element.get("Type") != REL + "/hyperlink":
                                raise WorkbookRejected("EXTERNAL_CONNECTION")
            workbook = roots["xl/workbook.xml"]
            relationships = {e.get("Id"): e for e in roots["xl/_rels/workbook.xml.rels"]}
            sheets = workbook.findall(f"{{{NS}}}sheets/{{{NS}}}sheet")
            if not 1 <= len(sheets) <= 16:
                raise WorkbookRejected("SHEET_LIMIT")
            result, total_grid = [], 0
            for sheet in sheets:
                relation = relationships[sheet.get(f"{{{REL}}}id")]
                if relation.get("Type") != REL + "/worksheet":
                    raise WorkbookRejected("UNSUPPORTED_SHEET")
                target = relation.get("Target", "")
                part = posixpath.normpath(posixpath.join("xl", target)).lstrip("/")
                if not part.startswith("xl/"):
                    raise WorkbookRejected("ZIP_UNSAFE_PATH")
                root = roots[part]
                max_row = max_col = 1
                seen_cells, seen_rows = set(), set()
                hidden_rows = []
                for row in root.findall(f"{{{NS}}}sheetData/{{{NS}}}row"):
                    number = int(row.get("r", "0"))
                    if not 1 <= number <= MAX_ROWS or number in seen_rows:
                        raise WorkbookRejected("ROW_LIMIT_OR_DUPLICATE")
                    seen_rows.add(number)
                    max_row = max(max_row, number)
                    if row.get("hidden") == "1":
                        hidden_rows.append(number)
                    for cell in row.findall(f"{{{NS}}}c"):
                        ref = cell.get("r", "")
                        if not re.fullmatch(r"[A-Z]{1,3}[1-9][0-9]*", ref):
                            raise WorkbookRejected("INVALID_CELL_REFERENCE")
                        r, c = coordinate_to_tuple(ref)
                        if r != number or c > MAX_COLS or ref in seen_cells:
                            raise WorkbookRejected("CELL_LIMIT_OR_DUPLICATE")
                        seen_cells.add(ref)
                        max_col = max(max_col, c)
                total_grid += max_row * max_col
                if total_grid > MAX_GRID:
                    raise WorkbookRejected("CELL_LIMIT_OR_DUPLICATE")
                rel_path = posixpath.join(posixpath.dirname(part), "_rels",
                                         posixpath.basename(part) + ".rels")
                rels = {e.get("Id"): e for e in roots.get(rel_path, [])}
                links = {}
                for link in root.findall(f"{{{NS}}}hyperlinks/{{{NS}}}hyperlink"):
                    ref = link.get("ref", "")
                    if ":" in ref:
                        raise WorkbookRejected("UNSUPPORTED_HYPERLINK_RANGE")
                    relation = rels.get(link.get(f"{{{REL}}}id"))
                    links[ref] = (
                        relation.get("Target", "") if relation is not None
                        else "#" + link.get("location", "")
                    )
                tables = []
                for node in root.findall(f"{{{NS}}}tableParts/{{{NS}}}tablePart"):
                    target = rels[node.get(f"{{{REL}}}id")].get("Target", "")
                    table_part = posixpath.normpath(posixpath.join(
                        posixpath.dirname(part), target)).lstrip("/")
                    table = roots[table_part]
                    style = table.find(f"{{{NS}}}tableStyleInfo")
                    tables.append({**table.attrib,
                                   "style": dict(style.attrib) if style is not None else None})
                result.append({
                    "name": sheet.get("name"), "state": sheet.get("state", "visible"),
                    "max_row": max_row, "max_column": max_col, "hyperlinks": links,
                    "hidden_rows": hidden_rows,
                    "columns": [dict(c.attrib) for c in root.findall(f"{{{NS}}}cols/{{{NS}}}col")],
                    "merged": [e.get("ref") for e in root.findall(
                        f"{{{NS}}}mergeCells/{{{NS}}}mergeCell")],
                    "tables": tables,
                    "auto_filter": [dict(e.attrib) for e in root.findall(f"{{{NS}}}autoFilter")],
                    "panes": [dict(e.attrib) for e in root.findall(
                        f"{{{NS}}}sheetViews/{{{NS}}}sheetView/{{{NS}}}pane")],
                })
            return result
    except WorkbookRejected:
        raise
    except (BadZipFile, KeyError, ValueError, TypeError, OSError, expat.ExpatError, ET.ParseError):
        raise WorkbookRejected("INVALID_XLSX") from None


def open_readonly(data: bytes):
    # keep_links=False is defense in depth: external workbook links were already rejected.
    with warnings.catch_warnings(record=True):
        try:
            return load_workbook(
                io.BytesIO(data), read_only=True, data_only=False, keep_links=False
            )
        except Exception:
            raise WorkbookRejected("INVALID_XLSX") from None