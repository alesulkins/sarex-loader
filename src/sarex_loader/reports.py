"""Publish private JSON/Markdown to a fresh separate directory, never overwrite."""

import csv
import hashlib
import html
import io
import json
import os
import unicodedata
from pathlib import Path

from sarex_loader.config import local_path
from sarex_loader.file_safety import directory_fd
from sarex_loader.messages import describe
from sarex_loader.safety import ValidationError


def literal(value):
    # No raw Markdown/HTML/links from cells or filenames become executable markup.
    value = html.escape(str(value), quote=True).replace("|", "&#124;")
    value = "".join(
        f"&#{ord(c)};" if c in "`[]()*_\\" or unicodedata.category(c).startswith('C')
        else c for c in value
    )
    return "<code>" + value + "</code>"


def markdown(report: dict) -> str:
    lines = ["# Аудит Excel", "", "Локальный dry-run. Данные не исправлялись. "
             "URL классифицированы по синтаксису, доступность не проверялась.", ""]
    for registry in report["registries"]:
        lines += ["## Реестр", "", "Файл: " + literal(registry["file"]), "",
                  "Тип: " + literal(registry["registry_type"]), "",
                  "Статус: " + registry["status"], "",
                  "SHA-256: " + literal(registry["sha256"]), "",
                  "| Метрика | Значение |", "|---|---|"]
        for key, value in registry["summary"].items():
            lines.append("| " + literal(key) + " | " + literal(
                json.dumps(value, ensure_ascii=False)) + " |")
        lines += ["", "### Замечания", "",
                  "| Уровень | Код | Лист | Строка | Ячейка | Все совпадения |",
                  "|---|---|---|---|---|---|"]
        for issue in registry["issues"]:
            values = [issue[k] for k in ("severity", "code", "sheet", "row", "column")]
            values.append(json.dumps(issue["locations"], ensure_ascii=False))
            lines.append("| " + " | ".join(literal(v) for v in values) + " |")
        lines += ["", "Точные номера, значения, типы ячеек и адреса строк — в JSON. "
                  "Формулы не вычислялись; тексты формул и URL не копируются в отчёт.", ""]
    lines += ["## Пересечения ID между файлами", "",
              literal(json.dumps(report["cross_registry"], ensure_ascii=False)), ""]
    return "\n".join(lines)


def write_reports(output: Path, report: dict, input_roots: list[Path]) -> None:
    payloads = {
        "excel_audit.json": json.dumps(report, ensure_ascii=False, indent=2,
                                       allow_nan=False).encode("utf-8"),
        "excel_audit.md": markdown(report).encode("utf-8"),
    }
    _write_bundle(output, payloads, input_roots)


def write_match_reports(output: Path, report: dict, input_roots: list[Path]) -> None:
    lines = ['# Локальное сопоставление PDF', '',
             'Dry-run. MATCHED — только точное локальное соответствие. '
             'Папки не проверены в Sarex; загрузка не разрешена.', '',
             literal(json.dumps(report['summary'], ensure_ascii=True)), '',
             '| Файл | Категория | Номер | Группа кандидатов | Причины | Путь |',
             '|---|---|---|---|---|---|']
    for item in report['files']:
        values = [item[key] for key in ('filename', 'category', 'number', 'candidate_group',
                                        'reasons', 'proposed_path')]
        lines.append('| ' + ' | '.join(literal(value) for value in values) + ' |')
    lines += ['', 'Кандидаты и адреса Excel (группа → candidate_ids → кандидаты):', '',
              '| ID кандидата | Источник | Лист | Строка | Номер | Статус | Причины |',
              '|---|---|---|---|---|---|---|']
    for i, candidate in enumerate(report['candidates']):
        values = [i] + [candidate[k] for k in ('source', 'sheet', 'row', 'number',
                                              'status', 'reasons')]
        lines.append('| ' + ' | '.join(literal(v) for v in values) + ' |')
    lines += ['', 'Полные источники, группы кандидатов/повторов и SHA-256 — в JSON.', '']
    # ASCII escaping also safely preserves surrogateescaped filenames on POSIX.
    payloads = {
        'pdf_match.json': json.dumps(report, ensure_ascii=True, indent=2,
                                     allow_nan=False).encode('utf-8'),
        'pdf_match.md': '\n'.join(lines).encode('utf-8'),
    }
    _write_bundle(output, payloads, input_roots)


def _write_bundle(output: Path, payloads: dict[str, bytes], input_roots: list[Path]) -> None:
    if not input_roots:
        raise ValidationError("Для записи отчётов нужны явные входные каталоги.")
    output = local_path(output).absolute()
    for root in input_roots:
        root = local_path(root).absolute()
        if output.is_relative_to(root) or root.is_relative_to(output):
            raise ValidationError("Отчёты должны находиться отдельно от входных каталогов.")
    # All data is serialized before reserving the directory. COMPLETE is committed last.
    complete = {name: hashlib.sha256(data).hexdigest() for name, data in payloads.items()}
    payloads["COMPLETE.json"] = json.dumps(complete, sort_keys=True).encode("utf-8")
    try:
        if os.name == 'nt':
            from sarex_loader.windows_files import write_bundle

            write_bundle(output, payloads)
            return
        with directory_fd(output.parent) as parent:
            os.mkdir(output.name, mode=0o700, dir_fd=parent)  # Exclusive directory reservation.
            fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                for name, data in payloads.items():
                    file_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                      0o600, dir_fd=fd)
                    with os.fdopen(file_fd, "wb") as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(parent)
    except OSError:
        # Retain partial artifacts for diagnosis; never delete or overwrite anything.
        raise ValidationError(
            "Не удалось сохранить отчёты. Каталог должен быть новым; "
            "без COMPLETE.json результат незавершён."
        ) from None


def write_pipeline_reports(output: Path, report: dict, input_roots: list[Path]) -> None:
    report = dict(report)
    snapshot = report.pop('tree_snapshot', None)
    lines = ['# Локальный конвейер Sarex Loader', '',
             'Dry-run. LOCAL_MATCH не разрешает загрузку. Папки и URL не проверены на сервере.',
             'Checkpoint относится только к mock; OUTCOME_UNKNOWN запрещает повтор.', '',
             '| Операция | Статус | Файл | Лист/строка | Номер | Путь | Mock-состояние |',
             '|---|---|---|---|---|---|---|']
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, quoting=csv.QUOTE_ALL)
    writer.writerow(['ID операции', 'Код статуса', 'PDF', 'Лист и строка Excel', 'Номер',
                     'Рассчитанный путь', 'Состояние симуляции', 'Описание'])
    for key, operation in report['operations'].items():
        values = [key, operation['status'], operation.get('filename', ''),
                  f"{operation['sheet']}:{operation['row']}", operation['number'],
                  json.dumps(operation['proposed_path'], ensure_ascii=True),
                  report['mock_checkpoints'][key]['state']]
        lines.append('| ' + ' | '.join(literal(v) for v in values) + ' |')
        # Always text in CSV, even when leading whitespace hides a formula prefix.
        writer.writerow(["'" + str(value) for value in [*values, describe(operation['status'])]])
    lines += ['', 'Аудит с адресами замечаний, строки без PDF, общие группы совпадений и '
              'контрольные суммы приведены в pipeline.json. Ссылки не генерировались.', '']
    payloads = {
        'pipeline.json': json.dumps(report, ensure_ascii=True, indent=2,
                                    allow_nan=False).encode('utf-8'),
        'pipeline.md': '\n'.join(lines).encode('utf-8'),
        'pipeline.csv': stream.getvalue().encode('utf-8-sig', errors='backslashreplace'),
    }
    if snapshot is not None:
        from sarex_loader.tree_source import snapshot_payloads

        payloads.update(snapshot_payloads(snapshot, report['tree']['max_response_bytes']))
    _write_bundle(output, payloads, input_roots)


def write_gateway_import_reports(output: Path, report: dict, input_roots: list[Path]) -> None:
    lines = ['# Локальная выгрузка Gateway: кандидаты URL', '',
             'Excel не изменён. Ссылки — неподтверждённые кандидаты, выбора документов нет.',
             'Полнота, пагинация и актуальность выгрузки не подтверждены. '
             'Отсутствие ID в ответе не доказывает отсутствие документа в Sarex.', '',
             '## Проверка известных PDF', '', '| ID | Статус в выгрузке |', '|---|---|']
    for item in report['known_documents']:
        lines.append('| ' + literal(item['id']) + ' | ' + literal(item['status']) + ' |')
    lines += ['', '## Полнота и ограничения', '',
              literal(json.dumps(report['coverage'], ensure_ascii=True)), '',
              '## Строки Excel', '',
              '| Лист | Строка | ID инспекции | Статус | ID папки | Группа PDF | Группа папок |',
              '|---|---|---|---|---|---|---|']
    for item in report['rows']:
        values = [item[k] for k in ('sheet', 'row', 'id', 'status', 'folder_id',
                                    'candidate_group', 'folder_group')]
        lines.append('| ' + ' | '.join(literal(v) for v in values) + ' |')
    lines += ['', '## Общие группы кандидатов', '',
              '| Группа | ID папки | ID документов | Неоднозначность |', '|---|---|---|---|']
    for item in report['candidate_groups']:
        lines.append('| ' + ' | '.join(literal(item[k]) for k in (
            'group_id', 'folder_id', 'document_ids', 'ambiguous')) + ' |')
    lines += ['', 'Кандидаты ссылок, причины ошибок и хеши источников — в JSON. '
              'Имена из Gateway, неизвестные поля ответа и токены не включены.', '']
    _write_bundle(output, {
        'gateway_import.json': json.dumps(report, ensure_ascii=True, indent=2,
                                          allow_nan=False).encode(),
        'gateway_import.md': '\n'.join(lines).encode(),
    }, input_roots)
