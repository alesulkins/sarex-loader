"""Read-only inspection registry validation. No matching of PDFs or remote documents."""

import hashlib
import json
import math
import re
import unicodedata
import warnings
from collections import Counter, defaultdict
from datetime import date, datetime, time, timedelta
from functools import partial
from urllib.parse import parse_qsl, urlsplit
from xml.etree.ElementTree import ParseError

from openpyxl.utils.cell import get_column_letter

from sarex_loader.config import RunConfig
from sarex_loader.excel_io import WorkbookRejected, open_readonly, preflight
from sarex_loader.file_safety import read_snapshot
from sarex_loader.safety import ValidationError

HEADERS = ("ID", "Дата", "П_Офис", "Подрядчик", "Номер", "URL")


def blank(value):
    return value is None or isinstance(value, str) and not value.strip()


def suspicious_text(value):
    return isinstance(value, str) and (
        value != value.strip() or "\u00a0" in value
        or any(unicodedata.category(c) in {"Cc", "Cf"} for c in value)
    )


def json_value(value):
    if isinstance(value, (date, datetime, time)):
        return value.isoformat()
    if isinstance(value, timedelta):
        return str(value)
    if isinstance(value, float) and not math.isfinite(value):
        return {"non_finite": str(value)}
    return value


def classify_url(value):
    """Classify syntax only; deliberately do not return URL values or signed queries."""
    if blank(value):
        return "EMPTY"
    if not isinstance(value, str):
        return "INVALID_TYPE"
    if len(value) > 8192 or suspicious_text(value) or any(c.isspace() for c in value):
        return "SUSPICIOUS"
    try:
        url = urlsplit(value)
        if url.scheme != "https":
            return "UNSAFE_SCHEME"
        if url.username is not None or url.password is not None:
            return "CREDENTIALS_IN_URL"
        if url.hostname != "lk.sarex.io" or url.port not in (None, 443):
            return "OTHER_ORIGIN"
        if url.fragment:
            return "SUSPICIOUS"
        if url.path.rstrip("/") == "/documentations":
            return "MISSING_DOCUMENT_ID"
        if re.fullmatch(r"/documentations/[1-9][0-9]*/?", url.path):
            return "DOCUMENT" if not url.query else "SUSPICIOUS_QUERY"
        uuid = r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}"
        if re.fullmatch(r"/workspaces-v2/" + uuid + r"/?", url.path):
            pairs = parse_qsl(url.query, keep_blank_values=True, max_num_fields=20)
            keys = [k for k, v in pairs]
            if len(keys) != len(set(keys)) or set(keys) - {"type", "back"}:
                return "SUSPICIOUS_QUERY"
            if dict(pairs).get("type") != "pdf":
                return "SUSPICIOUS_QUERY"
            return "WORKSPACE"
        return "UNRECOGNIZED_PATH"
    except ValueError:
        return "MALFORMED"


def group_duplicates(records, key_function):
    groups = defaultdict(list)
    for record in records:
        key = key_function(record)
        if key is not None:
            groups[key].append(record)
    return [group for group in groups.values() if len(group) > 1]


def audit_registry(config: RunConfig) -> dict:
    # Third-party parsing warnings can contain cell values. Keep only a diagnostic count.
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        report = _audit_registry(config)
    if caught:
        report["issues"].append({
            "code": "PARSER_WARNING", "severity": "warning", "file": report["file"],
            "registry_type": report["registry_type"], "sheet": None, "row": None,
            "column": None, "locations": [], "count": len(caught),
        })
        if report["status"] == "CLEAN":
            report["status"] = "ISSUES"
    return report


def _audit_registry(config: RunConfig) -> dict:
    source = str(config.excel)
    report = {
        "file": source, "registry_type": config.inspection_type, "sha256": None,
        "status": "REJECTED", "sheets": [], "records": [], "issues": [],
        "summary": {}, "duplicates": {},
    }

    def issue(code, *, sheet=None, row=None, column=None, severity="error", locations=None):
        report["issues"].append({
            "code": code, "severity": severity, "file": source,
            "registry_type": config.inspection_type, "sheet": sheet,
            "row": row, "column": column, "locations": locations or [],
        })

    def cell_issue(code, header, severity="error", *, sheet_name, row, columns):
        issue(code, sheet=sheet_name, row=row,
              column=f"{get_column_letter(columns[header] + 1)}{row}", severity=severity)

    workbook = None
    try:
        data = read_snapshot(config.excel, config.max_file_bytes)
        report["sha256"] = hashlib.sha256(data).hexdigest()
        metadata = preflight(data)
        workbook = open_readonly(data)
        report["epoch"] = workbook.epoch.isoformat()
        total_rows = blank_rows = formulas = errors = 0
        for meta, sheet in zip(metadata, workbook.worksheets, strict=True):
            if meta["name"] != sheet.title:
                raise WorkbookRejected("SHEET_MAPPING_MISMATCH")
            sheet.reset_dimensions()
            iterator = sheet.iter_rows(max_row=meta["max_row"], max_col=meta["max_column"])
            header_cells = next(iterator)
            headers = [c.value if c.data_type not in {"f", "e"} else "[FORMULA_OR_ERROR]"
                       for c in header_cells]
            for cell in header_cells:
                if cell.data_type in {"f", "e"}:
                    formulas += cell.data_type == "f"
                    errors += cell.data_type == "e"
                    issue("FORMULA" if cell.data_type == "f" else "EXCEL_ERROR",
                          sheet=sheet.title, row=1, column=cell.coordinate)
            duplicates = [h for h, n in Counter(h for h in headers
                                               if isinstance(h, str) and not blank(h)).items()
                          if n > 1]
            missing = [h for h in HEADERS if h not in headers]
            columns = {h: headers.index(h) for h in HEADERS if h in headers and h not in duplicates}
            schema_valid = not missing and not duplicates
            info = {k: v for k, v in meta.items() if k != "hyperlinks"}
            info.update({
                "headers": [json_value(h) for h in headers], "missing_columns": missing,
                "duplicate_headers": duplicates, "schema_valid": schema_valid,
                "rows": 0, "blank_rows": 0, "hyperlinks": len(meta["hyperlinks"]),
                "formats": {h: Counter() for h in HEADERS},
            })
            report["sheets"].append(info)
            if not schema_valid:
                issue("INVALID_HEADERS", sheet=sheet.title, row=1)
            if any(h not in HEADERS and not blank(h) for h in headers):
                issue("EXTRA_COLUMNS", sheet=sheet.title, row=1, severity="warning")
            if meta["state"] != "visible":
                issue("HIDDEN_SHEET", sheet=sheet.title, severity="warning")
            if meta["merged"]:
                issue("MERGED_CELLS", sheet=sheet.title, severity="warning")
            if meta["hidden_rows"]:
                issue("HIDDEN_ROWS", sheet=sheet.title, severity="warning",
                      locations=[{"sheet": sheet.title, "row": r} for r in meta["hidden_rows"]])
            if any(c.get("hidden") == "1" for c in meta["columns"]):
                issue("HIDDEN_COLUMNS", sheet=sheet.title, severity="warning")
            expected = {"Инспекции СК": "sk", "Инспекции ВК": "vk"}.get(sheet.title)
            if expected and expected != config.inspection_type:
                issue("REGISTRY_TYPE_MISMATCH", sheet=sheet.title)
            for row_number, cells in enumerate(iterator, 2):
                if all(c.value is None or c.value == "" for c in cells):
                    blank_rows += 1
                    info["blank_rows"] += 1
                    issue("BLANK_ROW", sheet=sheet.title, row=row_number, severity="warning")
                    continue
                total_rows += 1
                info["rows"] += 1
                for cell in cells:
                    if cell.data_type in {"f", "e"}:
                        formulas += cell.data_type == "f"
                        errors += cell.data_type == "e"
                        issue("FORMULA" if cell.data_type == "f" else "EXCEL_ERROR",
                              sheet=sheet.title, row=row_number, column=cell.coordinate)
                if not schema_valid:
                    continue
                fields = {h: cells[index] for h, index in columns.items()}
                values = {h: c.value if c.data_type not in {"f", "e"} else None
                          for h, c in fields.items()}
                record = {
                    "sheet": sheet.title, "row": row_number,
                    "registry_type": config.inspection_type, "id_key": None,
                    "number": json_value(values["Номер"]), "month": None, "date": None,
                    "number_is_text": isinstance(values["Номер"], str),
                    "office": json_value(values["П_Офис"]),
                    "contractor": json_value(values["Подрядчик"]),
                    # URLs and formulas are classified but not copied into reports.
                    "values": {h: json_value(v) for h, v in values.items() if h != "URL"},
                    "cell_types": {h: c.data_type for h, c in fields.items()},
                    "number_format": fields["Номер"].number_format,
                }
                report["records"].append(record)

                flag = partial(cell_issue, sheet_name=sheet.title, row=row_number, columns=columns)

                for h, c in fields.items():
                    info["formats"][h][c.number_format] += 1
                    if c.data_type in {"f", "e"}:
                        continue
                    if h != "URL" and blank(c.value):
                        flag("EMPTY_REQUIRED", h)
                    if suspicious_text(c.value):
                        flag("SUSPICIOUS_WHITESPACE_OR_UNICODE", h, "warning")
                    if isinstance(c.value, str) and c.value.startswith(("=", "+", "-", "@")):
                        flag("FORMULA_LIKE_TEXT", h, "warning")
                identifier = values["ID"]
                if type(identifier) is int and 0 < identifier <= 2**53 - 1:
                    record["id_key"] = str(identifier)
                elif isinstance(identifier, str) and re.fullmatch(r"[1-9][0-9]{0,14}", identifier):
                    record["id_key"] = identifier
                    flag("ID_STORED_AS_TEXT", "ID", "warning")
                elif not blank(identifier):
                    flag("INVALID_ID", "ID")
                number = values["Номер"]
                if not blank(number) and not isinstance(number, str):
                    flag("NUMBER_NOT_TEXT", "Номер")
                for h in ("П_Офис", "Подрядчик"):
                    if not blank(values[h]) and not isinstance(values[h], str):
                        flag("INVALID_TEXT_TYPE", h)
                value_date = values["Дата"]
                parsed_date = value_date if isinstance(value_date, (date, datetime)) else None
                if isinstance(value_date, str) and re.fullmatch(
                    r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[T ][0-9: .]+)?", value_date
                ):
                    try:
                        parsed_date = datetime.fromisoformat(value_date)
                        flag("DATE_STORED_AS_TEXT", "Дата", "warning")
                    except ValueError:
                        pass
                if parsed_date is not None:
                    record["date"] = parsed_date.isoformat()
                    record["month"] = parsed_date.strftime("%Y-%m")
                elif not blank(value_date):
                    flag("INVALID_DATE", "Дата")
                value_url = values["URL"]
                category = classify_url(value_url)
                if fields["URL"].data_type in {"f", "e"}:
                    category = "FORMULA_OR_ERROR"
                record["url_class"] = category
                record["url_hash"] = (
                    hashlib.sha256(value_url.encode()).hexdigest()
                    if isinstance(value_url, str) and not blank(value_url) else None
                )
                if category not in {"EMPTY", "DOCUMENT", "WORKSPACE"}:
                    flag("URL_" + category, "URL")
                coordinate = f"{get_column_letter(columns['URL'] + 1)}{row_number}"
                if coordinate in meta["hyperlinks"]:
                    link = meta["hyperlinks"][coordinate]
                    if value_url != link:
                        flag("HYPERLINK_MISMATCH", "URL")
                    record["hyperlink_class"] = classify_url(link)

        records = report["records"]

        def raw_number_key(r):
            return None if blank(r["number"]) else json.dumps(
                [r["cell_types"]["Номер"], json_value(r["number"])], ensure_ascii=False
            )

        def folder_key(r, exact=False):
            if (not r["number_is_text"] or blank(r["number"])
                    or not all(isinstance(r[k], str) and not blank(r[k])
                               for k in ("office", "contractor")) or not r["month"]):
                return None
            return r["office"], r["contractor"], r["date" if exact else "month"], r["number"]

        groups = {
            "id": group_duplicates(records, lambda r: r["id_key"]),
            "number": group_duplicates(records, raw_number_key),
            "folder_number": group_duplicates(records, folder_key),
            "exact_date_number": group_duplicates(records, lambda r: folder_key(r, True)),
            "url": group_duplicates(records, lambda r: r["url_hash"]),
        }
        normalized = group_duplicates(records, lambda r: (
            " ".join(unicodedata.normalize("NFKC", r["number"]).split()).casefold()
            if r["number_is_text"] and not blank(r["number"]) else None
        ))
        groups["normalization_collision"] = [
            group for group in normalized if len({r["number"] for r in group}) > 1
        ]
        for name, duplicates in groups.items():
            report["duplicates"][name] = []
            for group in duplicates:
                locations = [{"sheet": r["sheet"], "row": r["row"]} for r in group]
                report["duplicates"][name].append({"locations": locations})
                issue("DUPLICATE_" + name.upper(), sheet=group[0]["sheet"], row=group[0]["row"],
                      severity="warning" if name == "url" else "error", locations=locations)
        dates = [r["date"] for r in records if r["date"]]
        report["summary"] = {
            "rows": total_rows, "validated_rows": len(records), "blank_rows": blank_rows,
            "url_classes": dict(Counter(r["url_class"] for r in records)),
            "empty_required": {h: sum(blank(r["values"][h])
                                      and r["cell_types"][h] not in {"f", "e"} for r in records)
                               for h in HEADERS if h != "URL"},
            "unique_ids": len({r["id_key"] for r in records if r["id_key"] is not None}),
            "unique_numbers": len({raw_number_key(r) for r in records if not blank(r["number"])}),
            "unique_urls": len({r["url_hash"] for r in records if r["url_hash"]}),
            "duplicate_counts": {k: {"groups": len(v), "rows": sum(len(g) for g in v)}
                                 for k, v in groups.items()},
            "formulas": formulas, "excel_errors": errors,
            "hyperlinks": sum(m["hyperlinks"] for m in report["sheets"]),
            "date_min": min(dates) if dates else None, "date_max": max(dates) if dates else None,
            "months": dict(sorted(Counter(r["month"] for r in records if r["month"]).items())),
            "numbers_with_slash": sum(isinstance(r["number"], str) and "/" in r["number"]
                                      for r in records),
        }
        # Abort publication if Excel changed while parsing. No original is ever saved.
        current_hash = hashlib.sha256(
            read_snapshot(config.excel, config.max_file_bytes)
        ).hexdigest()
        if current_hash != report["sha256"]:
            raise WorkbookRejected("SOURCE_CHANGED")
        report["status"] = "ISSUES" if report["issues"] else "CLEAN"
    except (WorkbookRejected, ValidationError) as exc:
        issue(exc.code if isinstance(exc, WorkbookRejected) else "INPUT_READ_REJECTED")
        report["status"] = "REJECTED"
    except (ValueError, TypeError, KeyError, IndexError, OverflowError, ParseError):
        issue("INVALID_CELL_OR_WORKBOOK_STRUCTURE")
        report["status"] = "REJECTED"
    finally:
        if workbook is not None:
            workbook.close()
    return report


def combine_reports(registries: list[dict]) -> dict:
    """Cross-file reuse is informational; duplicate decisions stay registry-scoped."""
    cross = []
    for i, first in enumerate(registries):
        for second in registries[i + 1:]:
            shared = {r["id_key"] for r in first["records"] if r["id_key"]} & {
                r["id_key"] for r in second["records"] if r["id_key"]}
            cross.append({
                "files": [first["file"], second["file"]],
                "types": [first["registry_type"], second["registry_type"]],
                "shared_id_values": len(shared), "action": "NONE_REVIEW_SCOPE",
            })
    return {"schema_version": 1, "dry_run": True, "network_enabled": False,
            "source_write_enabled": False, "registries": registries, "cross_registry": cross}