"""Customer upload: reviewed fresh routes, permanent intents and the shared uploader."""

import hashlib
import json
import os
import sys
from collections import Counter
from contextlib import ExitStack, redirect_stdout
from types import SimpleNamespace

from sarex_loader.api_models import ApiError
from sarex_loader.cooperative_stop import stop_after_file
from sarex_loader.excel_commit import commit_urls
from sarex_loader.excel_copy import URLUpdate, make_url_copy
from sarex_loader.file_safety import read_snapshot
from sarex_loader.folder_resolver import FolderResolver, collision_key
from sarex_loader.gateway_retry import GetRetrier
from sarex_loader.gateway_tree import gateway_login
from sarex_loader.gateway_tree_policy import GatewayTreeReadPolicy
from sarex_loader.journal import BATCH_CONFIRMATION_POLICY, Journal, fingerprint
from sarex_loader.local_moves import execute_moves
from sarex_loader.matching import extract_number
from sarex_loader.messages import describe
from sarex_loader.pdf_scan import scan_pdfs
from sarex_loader.production_scope import ProductionScope, journal_path, operation_key
from sarex_loader.profile_auth import use_settings
from sarex_loader.reports import _write_bundle
from sarex_loader.safety import ValidationError
from sarex_loader.single_test_scope import TEST_DISK_ID
from sarex_loader.tree_acceptance import operational_tree
from sarex_loader.tree_source import add_response
from sarex_loader.upload_preview import preview_payloads
from sarex_loader.upload_workflow import _execute_batch


def confirm(plan, path, *, ask=input):
    # The normal worker output is redirected to the log. Consent stays on the terminal.
    with redirect_stdout(sys.__stdout__):
        print("План загрузки: " + str(path))
        print(
            f"PDF к обработке: {len(plan['operations'])}; "
            f"перемещений в «не найдено»: {len(plan['moves'])}."
        )
        print("SHA-256 плана: " + plan["sha256"])
        return (
            ask(
                "Разрешить этот план: загрузку PDF, запись URL в переданный Excel "
                "и указанные локальные перемещения? Введите «да»: "
            ).strip()
            == "да"
        )


def _update(candidate, identifier):
    return URLUpdate(
        candidate["sheet"],
        candidate["row"],
        candidate["id"],
        candidate["number"],
        f"https://lk.sarex.io/documentations/{identifier}",
    )


def _reason(file, reason):
    file["reasons"] = list(dict.fromkeys([*file["reasons"], reason]))
    file["status"] = "UPLOAD_SKIPPED"
    file["status_description"] = "Пропущен"
    file["reason_description"] = "; ".join(describe(r) for r in file["reasons"])


def prepare_operations(config, index, report, pdf, journal):
    """No network or mutations. Hash one PDF at a time and retain every independent error."""
    contents = {f["filename"]: f for f in scan_pdfs(pdf)}
    hashes = Counter(f["sha256"] for f in contents.values() if f["sha256"])
    checkpoints = journal.checkpoints()
    operations, selected = {}, {}
    for file in report["files"]:
        content = contents.get(file["filename"])
        if not content or content["reason"] or content["identity"] != file["identity"]:
            _reason(file, (content or {}).get("reason") or "PDF_CHANGED")
            continue
        file["reasons"] = [r for r in file["reasons"] if r != "PDF_CONTENT_NOT_VERIFIED"]
        if hashes[content["sha256"]] > 1:
            _reason(file, "DUPLICATE_SHA256")
        if (
            file["category"] != "MATCHED"
            or len(file["excel_candidates"]) != 1
            or not file["folder_id"]
            or set(file["reasons"]) - {"REMOTE_DOCUMENT_EXISTS"}
        ):
            continue
        candidate = file["excel_candidates"][0]
        item = {
            "mode": "production-upload-v1",
            "status": "LOCAL_MATCH",
            "confirmation_policy": BATCH_CONFIRMATION_POLICY,
            "registry_type": file["registry_type"],
            "number": candidate["number"],
            "target_folder_id": str(config.tree.root_ids[0]),
            "disk_id": TEST_DISK_ID,
            "resolved_folder_id": file["folder_id"],
            "resolved_path_ids": list(index.documents[file["folder_id"]].path_ids),
            "filename": file["filename"],
            "pdf_sha256": content["sha256"],
            "document_type": "pdf",
            "file_key": "pdf",
            "bundle_date": candidate["date"][:10] + "T12:00:00+03:00",
        }
        key = operation_key(item)
        previous = checkpoints.get(key)
        if previous and journal.operation(key) != item:
            _reason(file, "Инспекция уже зарегистрирована с другим PDF или назначением.")
            continue
        remote = set(file["remote_document_ids"])
        own = {previous["document_id"]} if previous and previous["document_id"] else set()
        if remote - own:
            _reason(file, "REMOTE_DOCUMENT_EXISTS")
            continue
        if previous and previous["state"] != "PLANNED" and remote != own:
            _reason(file, "Ранее созданный документ не подтверждён свежим деревом.")
            continue
        operations[key], selected[key] = item, file
    return operations, selected


def fresh_children(config, index, folder, provider):
    metadata = {}
    raw = GetRetrier().fetch(
        GatewayTreeReadPolicy(config.tree.disk_id, folder, config.tree.max_response_bytes),
        provider,
        metadata,
    )
    if metadata.get("header_next_page_hint"):
        raise ValidationError("TREE_PAGINATION_UNSUPPORTED")
    fresh = FolderResolver()
    add_response(fresh, raw, config.tree.max_response_bytes, queried_folder=folder)
    if fresh.documents[folder] != index.documents[folder] or set(
        index.children.get(folder, {})
    ) - set(fresh.children.get(folder, {})):
        raise ValidationError("TREE_SNAPSHOT_CHANGED: изменилась папка или исчезли её дети.")
    return fresh.children.get(folder, {})


def run(config, index, report, pdf, excel, output, settings, *, no_move=False, ask=input):
    from sarex_loader.folder_ledger import FolderLedger
    from sarex_loader.folder_ledger import journal_path as folder_journal_path
    from sarex_loader.production_folders import finish as finish_folders
    from sarex_loader.production_folders import prepare_plans

    if not operational_tree(index):
        raise ValidationError("Нужен завершённый обход корня без ошибок GET и пропущенных веток.")
    protected = [excel.parent, pdf, journal_path()]
    snapshot = read_snapshot(excel, 64 * 1024**2)
    if hashlib.sha256(snapshot).hexdigest() != report["registry_sources"][0]["sha256"]:
        raise ValidationError("Excel изменился после расчёта маршрутов.")
    result = {
        "uploaded": 0,
        "already_confirmed": 0,
        "urls_written": 0,
        "errors": [],
        "stopped": False,
        "cancelled": False,
        "receipts": [],
        "moves": [],
        "folders": [],
    }
    backup = output.parent / (output.name + "-backups")
    backup.mkdir(mode=0o700)
    with Journal(journal_path(), [excel.parent, pdf]) as journal, ExitStack() as stack:
        folder_ledger = None
        if settings.allow_folder_creation or folder_journal_path().exists():
            folder_ledger = stack.enter_context(FolderLedger([excel.parent, pdf]))
        # Also checks unknown operations unrelated to the currently selected files/root.
        journal.register_production({})
        operations, selected = prepare_operations(config, index, report, pdf, journal)
        folder_plans = (prepare_plans(config, index, report)
                        if settings.allow_folder_creation else [])
        if settings.allow_folder_creation:
            eligible = {(p['parent_id'], p['month']) for p in folder_plans}
            for plan in report.get('planned_folders', []):
                plan['creation_blockers'] = [r for r in plan['creation_blockers']
                                             if r != 'FOLDER_CREATION_DISABLED']
                plan['creation_allowed'] = (plan['parent_id'], plan['month']) in eligible
                if not plan['creation_allowed']:
                    plan['creation_blockers'].append(
                        'Нет PDF, прошедших все проверки для создания.')
        blocked_moves = {f["local_path"] for f in report["files"]
                         if f["status"] == "UPLOAD_SKIPPED"}
        moves = ([] if no_move else [m for m in report.get("local_move_plan", [])
                                    if m["source"] not in blocked_moves])
        plan = {
            "operations": operations,
            "moves": moves,
            "excel": str(excel),
            "excel_sha256": hashlib.sha256(snapshot).hexdigest(),
        }
        plan["sha256"] = fingerprint(plan)
        plan_dir = output.parent / (output.name + "-approved-plan")
        _write_bundle(
            plan_dir,
            {
                "plan.json": json.dumps(plan, ensure_ascii=False, indent=2).encode(),
                "ПЛАН.md": (
                    "# План загрузки\n\n"
                    + "\n".join(
                        f"- {f['filename']} → {f['full_path']} (ID {f['folder_id']})"
                        for f in selected.values()
                    )
                    + "\n\nЛокальные перемещения:\n"
                    + "\n".join(f"- {m['source']} → {m['destination']}" for m in moves)
                ).encode(),
            },
            protected,
        )
        if operations or moves:
            result["cancelled"] = not confirm(plan, plan_dir / "ПЛАН.md", ask=ask)
        if not result["cancelled"] and (operations or moves):

            def verify():
                if (
                    read_snapshot(excel, 64 * 1024**2) != snapshot
                    or excel.with_name("~$" + excel.name).exists()
                    or not excel.stat().st_mode & 0o222
                    or not os.access(excel, os.W_OK)
                ):
                    raise ValidationError("Excel открыт, изменён или недоступен для записи.")

            verify()
            # Validate workbook structure and each destination cell before any resource POST.
            make_url_copy(
                snapshot,
                hashlib.sha256(snapshot).hexdigest(),
                [_update(f["excel_candidates"][0], 1) for f in selected.values()],
                approved_document_ids=(1,),
            )
            journal.register_production(operations)
            scope = ProductionScope(
                config.tree.root_ids[0],
                index.documents[config.tree.root_ids[0]].path_ids,
                operations,
                fingerprint(operations),
            )

            def save(key, identifier):
                nonlocal snapshot
                receipt = commit_urls(
                    excel,
                    snapshot,
                    [_update(selected[key]["excel_candidates"][0], identifier)],
                    backup_dir=backup,
                    approved_document_ids=(identifier,),
                )
                if not receipt["disk_verified"]:
                    raise ValidationError("Сохранение URL в Excel не подтверждено.")
                result["receipts"].append(receipt)
                result["urls_written"] += receipt["urls_written"]
                snapshot = read_snapshot(excel, 64 * 1024**2)

            with use_settings(settings), gateway_login() as provider, stop_after_file() as stop:
                children, failures = {}, {}
                # Reconcile previously created documents before any independent new upload.
                ordered = sorted(
                    operations, key=lambda k: journal.checkpoint(k)["state"] == "PLANNED"
                )
                for key in ordered:
                    if stop():
                        result["stopped"] = True
                        break
                    item, file = operations[key], selected[key]
                    folder = item["resolved_folder_id"]
                    try:
                        if folder not in children and folder not in failures:
                            try:
                                children[folder] = fresh_children(config, index, folder, provider)
                            except (ApiError, ValidationError) as exc:
                                failures[folder] = describe(str(exc))
                        if folder in failures:
                            raise ValidationError(failures[folder])
                        own = journal.checkpoint(key)["document_id"]
                        if any(
                            d.id != own
                            and not d.is_folder
                            and (
                                collision_key(d.name) == collision_key(item["filename"])
                                or extract_number(d.name, config.separator)
                                in {item["number"], file.get("extracted_number")}
                            )
                            for d in children[folder].values()
                        ):
                            raise ValidationError("REMOTE_DOCUMENT_EXISTS")
                    except (ApiError, ValidationError) as exc:
                        _reason(file, describe(str(exc)))
                        result["errors"].append(
                            {"filename": item["filename"], "reason": describe(str(exc))}
                        )
                        continue
                    sent = _execute_batch(
                        SimpleNamespace(input_root=pdf, pdf_dir=pdf),
                        {"max_documents": 1},
                        {},
                        {key: item},
                        journal,
                        False,
                        False,
                        provider,
                        production=scope,
                        verify_sources=verify,
                        on_confirm=save,
                    )
                    for field in ("uploaded", "already_confirmed"):
                        result[field] += sent[field]
                    result["errors"].extend(sent["errors"])
                    if sent["errors"]:
                        _reason(file, "; ".join(describe(e["code"]) for e in sent["errors"]))
                    else:
                        file.update(
                            status="UPLOADED_AND_SAVED",
                            status_description="PDF подтверждён; URL сохранён",
                            reasons=[],
                            reason_description="",
                            ready_to_upload=False,
                        )
                    if sent["stopped"]:
                        result["stopped"] = True
                        break
                if not result["stopped"] and moves:
                    verify()
                    result["moves"] = execute_moves(
                        moves, output.parent / (output.name + "-moves"), protected=protected
                    )
        result["checkpoints"] = journal.checkpoints()
        if folder_plans and not result['cancelled'] and not result['stopped']:
            def verify_folder_sources():
                if read_snapshot(excel, 64 * 1024**2) != snapshot:
                    raise ValidationError('Excel изменился перед созданием папок.')
                contents = {f['filename']: f for f in scan_pdfs(pdf)}
                for file in report['files']:
                    if (file.get('parent_id'), file.get('month')) not in {
                            (p['parent_id'], p['month']) for p in folder_plans}:
                        continue
                    content = contents.get(file['filename'])
                    if not content or content['reason'] or content['identity'] != file['identity']:
                        raise ValidationError('PDF изменился перед созданием папки.')

            result['folders'] = finish_folders(folder_plans, config, index, folder_ledger, settings,
                                               verify_sources=verify_folder_sources, ask=ask)
            result['stopped'] = any(p['status'] == 'OUTCOME_UNKNOWN' for p in result['folders'])
    for file in report["files"]:
        file["reason_description"] = "; ".join(describe(r) for r in file["reasons"])
    report.update(
        result,
        mode="PRODUCTION_UPLOAD",
        dry_run=False,
        pdf_contents_read=True,
        write_enabled=not result["cancelled"],
        output_directory=str(output),
        local_moves_enabled=bool(result["moves"]),
        folder_creation_enabled=settings.allow_folder_creation,
        local_moves_audit_directory=str(output.parent / (output.name + "-moves")),
    )
    report["counts"].update(
        uploaded=result["uploaded"],
        urls_written=result["urls_written"],
        already_confirmed=result["already_confirmed"],
    )
    payloads = preview_payloads(report)
    if result['folders']:
        payloads['ПАПКИ.md'] = ('# Создание месячных папок\n\n'
            + '\n'.join(f"- {p['full_path']} (parent_id={p['parent_id']}): {p['description']}"
                        for p in result['folders'])
            + '\n\nВ новые папки PDF в этом запуске не загружались. '
            'После успешного создания повторите запуск.\n').encode()
    payloads["upload-result.json"] = json.dumps(result, ensure_ascii=False, indent=2).encode()
    _write_bundle(output, payloads, protected)
    return report
