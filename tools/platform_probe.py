"""Same synthetic inputs on Windows/macOS. No credentials or network operations."""

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Font

from sarex_loader.audit import HEADERS, audit_registry
from sarex_loader.config import RunConfig
from sarex_loader.excel_commit import commit_urls
from sarex_loader.excel_copy import URLUpdate
from sarex_loader.folder_resolver import FolderResolver, FolderRules
from sarex_loader.gateway_models import parse_gateway_search_documents
from sarex_loader.local_moves import move_one
from sarex_loader.matching import InspectionIndex, build_match_report
from sarex_loader.monthly_folders import filename_date_check, infer_month_name
from sarex_loader.pdf_scan import identity, scan_pdfs
from sarex_loader.safety import ValidationError


def require(value, message):
    if not value:
        raise RuntimeError(message)


def no_network(event, args):
    if event.startswith(("socket.connect", "socket.bind", "urllib.")):
        raise RuntimeError("Network is prohibited during synthetic validation")


def run():
    sys.addaudithook(no_network)
    with tempfile.TemporaryDirectory(prefix="sarex-platform-") as tmp:
        root = Path(tmp).resolve()
        source = root / "входные данные"
        source.mkdir()
        pdf = source / "PDF"
        pdf.mkdir()
        workbook = Workbook()
        workbook.active.title = "Реестр"
        workbook.active.append(HEADERS)
        workbook.active.append([1, datetime(2026, 1, 2, 13), "Офис", "Компания", "001", None])
        existing = "https://lk.sarex.io/documentations/1002"
        workbook.active.append([2, datetime(2026, 1, 2, 13), "Офис", "Компания", "002", existing])
        workbook.active["A2"].font = Font(bold=True)
        other = workbook.create_sheet("Другой лист")
        other.append(HEADERS)
        other.append([3, datetime(2026, 1, 2, 13), "Офис", "Компания", "003", existing])
        excel = source / "реестр.xlsx"
        workbook.save(excel)
        workbook.close()
        for name in ("2026-01-02-тест- 001.pdf", "2026-01-02-тест-999.pdf"):
            (pdf / name).write_bytes(b"%PDF-synthetic metadata only")
        config = RunConfig(command="audit", input_root=source, excel=excel, inspection_type="sk")
        registry = audit_registry(config)
        rules = FolderRules("1", {"Офис": "Офис"}, {"Компания": "Компания"}, "Инспекции")
        entries = list(scan_pdfs(pdf, metadata_only=True))
        matched = build_match_report(InspectionIndex([registry], {"sk": rules}), entries, "sk", "-")
        statuses = sorted((f["number"], f["category"]) for f in matched["files"])
        require(statuses == [("001", "MATCHED"), ("999", "NOT_FOUND")], "Matching differs")
        nodes = [
            {"id": i, "name": name, "path": ".".join(map(str, range(1, i + 1))), "is_folder": True}
            for i, name in enumerate(("Root", "Офис", "Компания", "Инспекции", "2026-01"), 1)
        ]
        index = FolderResolver()
        index.add(
            parse_gateway_search_documents(json.dumps({"documents": nodes}).encode()).documents
        )
        proposal, error = rules.propose(registry["records"][0])
        require(error is None, "No route")
        resolved = index.resolve(1, proposal["components"])
        require(resolved.folder_id == 5, "Wrong destination")
        snapshot = excel.read_bytes()
        backup = root / "резервные копии"
        backup.mkdir()
        update = URLUpdate("Реестр", 2, "1", "001", "https://lk.sarex.io/documentations/1001")
        receipt = commit_urls(
            excel, snapshot, [update], backup_dir=backup, approved_document_ids=(1001,)
        )
        require(receipt["disk_verified"], "Excel not verified on disk")
        require(Path(receipt["backup_file"]).read_bytes() == snapshot, "Bad backup")
        second = commit_urls(
            excel, snapshot, [update], backup_dir=backup, approved_document_ids=(1001,)
        )
        require(second["urls_written"] == 0, "Excel replay not idempotent")
        book = load_workbook(excel)
        values = [book["Реестр"]["F2"].value, book["Реестр"]["F3"].value]
        require(values == [update.url, existing], "URL cells differ")
        require(
            book["Реестр"]["A2"].font.bold and book["Другой лист"]["E2"].value == "003",
            "Excel formatting or unrelated sheet changed",
        )
        book.close()
        missing = pdf / "2026-01-02-тест-999.pdf"
        before = hashlib.sha256(missing.read_bytes()).hexdigest()
        target = pdf / "не найдено" / missing.name
        plan = {
            "source": str(missing),
            "destination": str(target),
            "identity": list(identity(missing.stat())),
        }
        move_one(plan)
        require(
            not missing.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == before,
            "Synthetic move changed content",
        )
        missing.write_bytes(b"Do not overwrite destination")
        plan["identity"] = list(identity(missing.stat()))
        try:
            move_one(plan)
        except (OSError, ValidationError):
            pass
        else:
            raise RuntimeError("Existing destination was overwritten")
        require(
            missing.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == before,
            "Collision did not preserve both files",
        )
        # All subprocess arguments are fixed. Help and blocked production load never authenticate.
        for args, code in [(["-help"], 0), (["-load", "sk"], 2), (["-load", "vk"], 2)]:
            completed = subprocess.run(  # noqa: S603
                [sys.executable, "-m", "sarex_loader", *args],
                capture_output=True,
                timeout=20,
                check=False,
            )
            require(completed.returncode == code, "CLI exit code differs")
        naming = infer_month_name(list(index.children[4].values()), "2026-02")
        conflict = filename_date_check("2025-01-02-тест-001.pdf", "2026-01-02")
        return {
            "platform": platform.system(),
            "python": platform.python_version(),
            "canonical": {
                "matching": statuses,
                "folder_id": resolved.folder_id,
                "month_name": naming["name"],
                "date_error": conflict["code"],
                "excel_urls": values,
                "excel_backup_verified": True,
                "excel_replay_writes": 0,
                "other_sheets_and_style_preserved": True,
                "move_content_preserved": True,
                "overwrite_blocked": True,
                "cli_load_blocked": True,
            },
            "sarex_requests": 0,
            "native_upload_tested": False,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Output already exists")
    result = run()
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print("Synthetic platform checks passed: " + result["platform"])
