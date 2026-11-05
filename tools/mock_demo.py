"""Offline customer smoke test using the actual upload workflow and a fresh journal."""

import argparse
import json
import os
import sys
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from openpyxl import Workbook

from sarex_loader.audit import HEADERS
from sarex_loader.config import RunConfig, checked_path
from sarex_loader.safety import ValidationError
from sarex_loader.upload_mock import UploadMockTransport
from sarex_loader.upload_workflow import run_upload_workflow


def no_network(event, args):
    if event.startswith(("socket.connect", "socket.bind", "urllib.")):
        raise RuntimeError("В этом тесте любые сетевые запросы запрещены.")


def run(root):
    if os.name == "nt":
        raise ValidationError(
            "Полная mock-загрузка ещё требует переноса POSIX-операций. "
            "На Windows используйте проверку совместимости в GitHub Actions."
        )
    root = root.absolute()
    checked_path(root.parent, directory=True)
    root.mkdir(mode=0o700)  # Must be NEW; never reset a journal or reuse an unknown operation.
    source = root / "синтетические входные данные"
    source.mkdir()
    pdfs = source / "PDF"
    pdfs.mkdir()
    workbook = Workbook()
    workbook.active.title = "Тест"
    workbook.active.append(HEADERS)
    for i, number in enumerate(("000123", "000124"), 1):
        workbook.active.append(
            [i, datetime(2026, 1, 2, 13), "Тестовый офис", "Тестовая компания", number, None]
        )
    workbook.save(source / "реестр.xlsx")
    workbook.close()
    for stem, number in [("новый", "000123"), ("дубликат-а", "000124"), ("дубликат-б", "000124")]:
        (pdfs / f"2026-01-02-{stem}-{number}.pdf").write_bytes(
            b"%PDF-1.4\n% Synthetic envelope " + number.encode() + b"\n%%EOF\n"
        )
    config = RunConfig(
        command="upload",
        input_root=source,
        excel="реестр.xlsx",
        inspection_type="sk",
        pdf_dir="PDF",
        target_folder_id="1",
        journal_dir=root / "новый mock журнал",
        output_dir=root / "первый запуск",
        filename_separator="-",
        office_folders={"Тестовый офис": "Офис"},
        contractor_folders={"Тестовая компания": "Компания"},
        inspection_folder="Инспекции",
    )
    original = UploadMockTransport.open
    calls = []

    def observed(transport, request):
        calls.append(request.method)
        return original(transport, request)

    with patch.object(UploadMockTransport, "open", observed):
        first = run_upload_workflow(config, simulate=True)
        first_posts = calls.count("POST")
        calls.clear()
        second = run_upload_workflow(
            replace(config, output_dir=root / "повторный запуск"), simulate=True
        )
        repeat_posts = calls.count("POST")
    duplicates = [f["filename"] for f in first["matching"]["files"] if f["category"] == "AMBIGUOUS"]
    if (
        first_posts != 4
        or repeat_posts != 0
        or len(duplicates) != 2
        or second["mock_upload"]["urls_written"] != 1
    ):
        raise ValidationError("Результат mock-проверки отличается от ожидаемого.")
    result = {
        "mode": "OFFLINE_MOCK_ONLY",
        "real_sarex_requests": 0,
        "simulated_posts_first_run": first_posts,
        "simulated_posts_repeat": repeat_posts,
        "synthetic_documents_created": 1,
        "duplicate_files_skipped": duplicates,
        "urls_in_each_test_copy": 1,
        "historical_journals_opened": 0,
    }
    (root / "result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(
        "Имитация завершена: 1 новый документ, 2 дубликата пропущены; "
        "повторная отправка — 0. Реальных запросов Sarex — 0."
    )
    print("Тестовые Excel, SQLite и отчёт: " + str(root))
    return result


def main():
    parser = argparse.ArgumentParser(description="Полная офлайн-имитация без доступа к Sarex.")
    parser.add_argument(
        "output", type=Path, help="Новый каталог результата; не должен существовать."
    )
    args = parser.parse_args()
    sys.addaudithook(no_network)
    try:
        run(args.output)
    except (ValidationError, OSError) as exc:
        print(
            "Ошибка: "
            + (
                str(exc)
                if isinstance(exc, ValidationError)
                else "Нужен новый доступный каталог; существующие файлы не перезаписываются."
            )
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
