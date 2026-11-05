"""Local workflows and explicitly confirmed integration with the closed single-test."""

import argparse
import sys
from collections.abc import Sequence

from sarex_loader.config import COMMANDS, INSPECTION_TYPES, load_config
from sarex_loader.console import configure_console
from sarex_loader.messages import describe, emit_report
from sarex_loader.safe_logging import Event, make_logger
from sarex_loader.safety import ValidationError


class SafeParser(argparse.ArgumentParser):
    def __init__(self, *args: object, **kwargs: object) -> None:
        kwargs["allow_abbrev"] = False
        super().__init__(*args, **kwargs)

    def error(self, message: str) -> None:
        # argparse normally repeats unknown arguments and invalid values (possibly secrets).
        raise ValidationError("Некорректные аргументы. Используйте --help; значения скрыты.")


def build_parser() -> argparse.ArgumentParser:
    parser = SafeParser(prog="sarex-loader", description="Локальный анализ Excel/PDF.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in COMMANDS:
        sub = subparsers.add_parser(command, help="Локальный анализ и dry-run без сети.")
        sub.add_argument("--config", help="Явный путь к локальному TOML без секретов.")
        sub.add_argument("--input-root", help="Разрешённый локальный каталог входных данных.")
        sub.add_argument(
            "--excel", help="Файл .xlsx внутри input-root; audit читает его без изменений."
        )
        sub.add_argument("--inspection-type", choices=INSPECTION_TYPES)
        sub.add_argument("--pdf-dir", help="Каталог PDF внутри input-root; нужен для upload/match.")
        sub.add_argument("--target-folder-id", help="Явный ID папки; существование не проверяется.")
        sub.add_argument("--dry-run", action="store_true", default=None,
                         help="Локальный режим по умолчанию; несовместим с live-подтверждением.")
        sub.add_argument("--execute", action="store_true", help="Запрещён.")
        if command == 'upload':
            sub.add_argument('--pdf-metadata-only', action='store_true',
                             help='Только имена/stat PDF, без чтения содержимого и записи SQLite.')
            sub.add_argument('--batch-config', help='Пакет через существующий live-транспорт.')
            sub.add_argument('--confirm-live-batch', action='store_true',
                             help='Разрешить просмотренную тестовую партию после подтверждения.')
            sub.add_argument('--expected-batch-plan-sha256', help='SHA256 preview партии.')
            sub.add_argument('--recover-batch-urls', action='store_true',
                             help='Preview пакетной GET-проверки известных ID; без ресурсных POST.')
            sub.add_argument('--confirm-batch-urls', action='store_true',
                             help='Выполнить просмотренную GET-проверку и сохранить копию.')
            sub.add_argument('--accept-document-only-urls', action='store_true',
                             help='URL по GET ID/path; связь Bundle не подтверждается.')
            sub.add_argument('--single-test-config',
                             help='Связать Excel с прежним single-test; по умолчанию preview.')
            sub.add_argument('--confirm-live-single', action='store_true',
                             help='Отдельное подтверждение ровно одного тестового документа.')
            sub.add_argument('--expected-upload-plan-sha256',
                             help='SHA256 просмотренного preview одиночной интеграции.')
            sub.add_argument('--register-single-plan', action='store_true',
                             help='Явная первичная регистрация нового Excel-плана без сети.')
            sub.add_argument('--recover-document-id', type=int,
                             help='Read-only сверка candidate ID для отдельной URL-копии.')
            sub.add_argument('--confirm-url-copy', action='store_true',
                             help='Разрешить auth/GET и копию после ручной сверки содержимого.')
            sub.add_argument('--mock-upload', action='store_true',
                             help='Симуляция Bundle/PDF/Document и новая mock-копия Excel.')
            sub.add_argument('--independent-records', action='store_true',
                             help='Только mock: обрабатывать независимые однозначные записи.')
        if command in COMMANDS:
            sub.add_argument("--output-dir", help="Новый каталог отчётов вне input-root.")
            sub.add_argument("--max-file-bytes", type=int, help="Лимит XLSX; по умолчанию 16 MiB.")
        if command in {"match", "upload", "fill-urls"}:
            sub.add_argument("--filename-separator", help="Явный разделитель перед номером.")
        if command == 'fill-urls':
            sub.add_argument('--recovery-config',
                             help='Отдельная конфигурация нескольких выгрузок.')
            sub.add_argument('--write-copy', action='store_true',
                             help='Создать только новую XLSX-копию.')
            sub.add_argument('--expected-plan-sha256', help='SHA256 просмотренного preview.')
            sub.add_argument('--gateway-json', help='Локальный JSON Gateway внутри input-root.')
            sub.add_argument('--max-gateway-bytes', type=int,
                             help='Лимит JSON: 1 MiB, максимум 8 MiB.')
        if command in {'upload', 'fill-urls'}:
            sub.add_argument('--job-config',
                             help='Файл путей СК/ВК; свежий Gateway, без записи Sarex.')
            sub.add_argument('--journal-dir', help='Приватный каталог SQLite вне исходных данных.')
            sub.add_argument('--read-tree', action='store_true',
                             help='Обновить метаданные через настроенный Gateway или Chrome.')
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    configure_console()
    supplied = list(sys.argv[1:] if argv is None else argv)
    if supplied and supplied[0] in {
            '-setup', '-preview', '-load', '-fill', '-help', '-test-pdf', '-folders'}:
        from sarex_loader.customer_launcher import main as customer_main

        return customer_main(supplied)
    logger = make_logger(sys.stderr)
    try:
        args = vars(build_parser().parse_args(argv))
        command = args.pop("command")
        job_path = args.pop('job_config', None)
        if job_path:
            from sarex_loader.customer import run_customer

            allowed = {'dry_run', 'read_tree', 'write_copy', 'expected_plan_sha256'}
            if any(value not in (None, False) for key, value in args.items() if key not in allowed):
                raise ValidationError('Не смешивайте файл запуска с другими режимами и путями.')
            result = run_customer(command, job_path, write_copy=args.get('write_copy', False),
                                  expected_plan=args.get('expected_plan_sha256'))
            emit_report({k: result[k] for k in ('mode', 'summary', 'counts', 'coverage',
                         'plan_sha256', 'output_directory', 'excel_written') if k in result})
            return 3 if result.get('counts', {}).get('problem_files') else 0
        config_path = args.pop("config")
        if args.pop("execute"):
            raise ValidationError("Режим execute запрещён.")
        mock_upload = args.pop('mock_upload', False)
        independent = args.pop('independent_records', False)
        single_path = args.pop('single_test_config', None)
        live_single = args.pop('confirm_live_single', False)
        upload_hash = args.pop('expected_upload_plan_sha256', None)
        register_single = args.pop('register_single_plan', False)
        recover_id = args.pop('recover_document_id', None)
        confirm_copy = args.pop('confirm_url_copy', False)
        read_tree = args.pop('read_tree', False)
        batch_path = args.pop('batch_config', None)
        pdf_metadata_only = args.pop('pdf_metadata_only', False)
        batch_confirm = args.pop('confirm_live_batch', False)
        batch_hash = args.pop('expected_batch_plan_sha256', None)
        batch_recover = args.pop('recover_batch_urls', False)
        batch_urls = args.pop('confirm_batch_urls', False)
        document_only = args.pop('accept_document_only_urls', False)
        if ((batch_confirm or batch_hash or batch_recover or batch_urls or document_only)
                and batch_path is None
                or batch_path is not None and (
                    mock_upload or independent or single_path)
                or (batch_confirm or batch_urls) and args.get('dry_run')):
            raise ValidationError('Несовместимые параметры пакетной интеграции.')
        if pdf_metadata_only and (mock_upload or single_path or batch_confirm
                                  or batch_recover or batch_urls):
            raise ValidationError('METADATA_PLAN_IS_READ_ONLY')
        if ((live_single or upload_hash is not None or register_single
             or recover_id is not None or confirm_copy) and single_path is None
                or single_path is not None and (mock_upload or independent)
                or (live_single or register_single or confirm_copy) and args.get('dry_run')
                or live_single and (register_single or recover_id is not None or confirm_copy)
                or register_single and (recover_id is not None or confirm_copy)
                or confirm_copy and recover_id is None):
            raise ValidationError('Несовместимые параметры одиночной интеграции.')
        if independent and not mock_upload:
            raise ValidationError('independent-records разрешён только с mock-upload.')
        recovery_path = args.pop('recovery_config', None)
        write_copy = args.pop('write_copy', False)
        plan_hash = args.pop('expected_plan_sha256', None)
        if recovery_path is not None:
            from sarex_loader.config import local_path
            from sarex_loader.recovery import run_recovery
            from sarex_loader.recovery_config import load_recovery_config

            output = args.pop('output_dir', None)
            if config_path is not None or any(v is not None for v in args.values()):
                raise ValidationError('Не смешивайте legacy и multi-export конфигурации.')
            report = run_recovery(load_recovery_config(recovery_path),
                                  output_dir=local_path(output).absolute() if output else None,
                                  write_copy=write_copy, expected_plan_sha256=plan_hash,
                                  read_tree=read_tree)
            emit_report(report)
            return 3 if (any(report['summary'][s] for s in ('AMBIGUOUS', 'INVALID_DATA'))
                         or any(r['errors'] for r in report['registries'])) else 0
        if write_copy or plan_hash is not None:
            raise ValidationError('Для копии нужен recovery-config.')
        config = load_config(command, {k: v for k, v in args.items() if v is not None}, config_path)
        if read_tree and config.tree is None:
            raise ValidationError('--read-tree требует конфигурацию общего дерева.')
        if batch_path is not None:
            from sarex_loader.upload_workflow import load_batch_config, run_upload_workflow

            result = run_upload_workflow(config, batch_config=load_batch_config(batch_path),
                                         confirm_live_batch=batch_confirm,
                                         expected_batch_plan=batch_hash,
                                         recover_batch_urls=batch_recover,
                                         confirm_batch_urls=batch_urls,
                                         document_only_urls=document_only, read_tree=read_tree,
                                         pdf_metadata_only=pdf_metadata_only)
            emit_report(result)
            return 3 if result.get('stopped') or result['blocked'] else 0
        if single_path is not None:
            from sarex_loader.single_test_config import load_single_test_config
            from sarex_loader.upload_workflow import run_upload_workflow

            result = run_upload_workflow(
                config, single_test_config=load_single_test_config(single_path),
                confirm_live_single=live_single, expected_upload_plan_sha256=upload_hash,
                register_single_plan=register_single, recover_document_id=recover_id,
                confirm_url_copy=confirm_copy, read_tree=read_tree)
            emit_report(result)
            return 0
        if config.command == 'fill-urls' and config.gateway_json is not None:
            from sarex_loader.gateway_import import import_gateway_candidates
            from sarex_loader.reports import write_gateway_import_reports

            report = import_gateway_candidates(config)
            if config.output_dir is not None:
                write_gateway_import_reports(config.output_dir, report, [config.input_root])
            emit_report({
                'command': 'fill-urls', 'mode': 'LOCAL_GATEWAY_JSON', 'dry_run': True,
                'network_enabled': False, 'write_enabled': False, 'excel_written': False,
                'journal_updated': False, 'status': report['status'],
                'summary': report['summary'], 'coverage': report['coverage'],
                'known_documents': report['known_documents'],
                'reports_written': config.output_dir is not None,
            })
            logger.info(Event.AUDIT.value)
            issues = (report['registry_status'] != 'CLEAN' or report['gateway_issues']
                      or any(k not in {'CANDIDATE_UNVERIFIED', 'EXISTING_URL'}
                             for k in report['summary']))
            return 3 if issues else 0
        if config.command in {'upload', 'fill-urls'}:
            from sarex_loader.pipeline import run_pipeline
            from sarex_loader.reports import write_pipeline_reports

            if config.command == 'upload' and mock_upload:
                from sarex_loader.cooperative_stop import stop_after_file
                from sarex_loader.upload_workflow import run_upload_workflow

                with stop_after_file() as should_stop:
                    report = run_upload_workflow(config, simulate=mock_upload,
                                                 allow_independent=independent, read_tree=read_tree,
                                                 stop_requested=should_stop)
            else:
                report = run_pipeline(config, read_tree=read_tree,
                                      pdf_metadata_only=pdf_metadata_only)
            if config.output_dir is not None and not mock_upload:
                write_pipeline_reports(config.output_dir, report, [config.input_root,
                                                                   config.journal_dir])
            emit_report({
                'command': config.command, 'status': report['status'], 'dry_run': True,
                'network_enabled': report['network_enabled'],
                'write_enabled': False, 'upload_authorized': False,
                'summary': report['summary'], 'outcome_unknown': report['outcome_unknown'],
                'row_summary': report['row_summary'],
                'journal_updated': not pdf_metadata_only,
                'reports_written': config.output_dir is not None,
                'mock_upload': report.get('mock_upload'),
                'tree': report.get('tree'),
            })
            logger.info(Event.AUDIT.value)
            if report.get('mock_upload', {}).get('status') == 'MOCK_STOPPED':
                print('Остановлено после текущего файла. Журнал и промежуточная копия Excel '
                      'сохранены. Для продолжения используйте тот же журнал и новый '
                      'каталог результатов.')
                return 130
            return 3 if (report['status'] == 'ISSUES' or
                         report.get('mock_upload', {}).get('url_errors')) else 0
        if config.command == "match":
            from sarex_loader.matching import match_local
            from sarex_loader.reports import write_match_reports

            report = match_local(config)
            if config.output_dir is not None:
                write_match_reports(config.output_dir, report, [config.input_root])
            issues = (any(count for key, count in report['summary'].items() if key != 'MATCHED')
                      or report['invalid_registry_rows'] or report['blocked_registry_types'])
            emit_report({
                'command': 'match', 'dry_run': True, 'network_enabled': False,
                'write_enabled': False, 'upload_authorized': False,
                'status': 'ISSUES' if issues else 'LOCAL_MATCH_ONLY',
                'summary': report['summary'], 'reports_written': config.output_dir is not None,
            })
            logger.info(Event.AUDIT.value)
            return 3 if issues else 0
        if config.command == "audit":
            # Lazy imports preserve inert package imports.
            from sarex_loader.audit import audit_registry, combine_reports
            from sarex_loader.reports import write_reports

            registry = audit_registry(config)
            if config.output_dir is not None:
                write_reports(config.output_dir, combine_reports([registry]), [config.input_root])
            errors = sum(i["severity"] == "error" for i in registry["issues"])
            emit_report({
                "command": "audit", "status": registry["status"], "dry_run": True,
                "network_enabled": False, "write_enabled": False,
                "rows": registry["summary"].get("rows", 0), "errors": errors,
                "warnings": sum(i["severity"] == "warning" for i in registry["issues"]),
                "reports_written": config.output_dir is not None,
            })
            logger.info(Event.AUDIT.value)
            return 3 if errors else 0
    except ValidationError as exc:
        logger.warning(Event.INVALID.value)
        print(describe(str(exc)), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        logger.warning(Event.INTERRUPTED.value)
        return 130
    except Exception:
        # Do not dump exceptions which might include confidential paths or future credentials.
        logger.error(Event.INTERNAL_ERROR.value)
        return 1
