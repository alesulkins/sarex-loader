# Аудит клиентской поставки rc.7

Дата: 05.11.2026. База: main fa04505; локальные изменения поставки rc.7.
Sarex не вызывался. Исходные клиентские документы, account.toml и исторические SQLite не менялись.

## Границы аудита

Построен граф импортов всех **102** Python-модулей src/sarex_loader,
включая отложенные импорты внутри функций. От пользовательских точек входа достижимы
**86** модулей. Сохранён также folder_creation — механизм изолированной
симуляции создания папок. Это проверка состава и зависимостей, не заявление
о формальном доказательстве корректности всех строк кода.

Все исходные модули сохранены в репозитории. В клиентский архив включены
**87** модулей и обязательные ресурсы. Из архива
исключены 15 самостоятельных диагностических модулей, не импортируемых
пользовательскими точками входа. Тесты контролируют замкнутость импортов ZIP.

## Что сохранено

- Preview СК/ВК и -load --dry-run, отчёты о будущих папках и назначениях.
- -test-pdf и отдельная подтверждаемая --send в фиксированную цель 99-Тест.
- Офлайн mock-upload, пропуск дубликатов, повторный запуск.
- Fill, рабочий load с подтверждением, общие клиенты и проверки безопасности.
- SQLite, UNKNOWN, блокировки, Windows handles, TLS, checkpoint/resume.
- folder_creation, monthly_folders и их тесты. **Реальное создание папок не
  подключено к CLI:** create_missing_months требует simulate=True и
  network_enabled=False. Смена одного флага не превращает симуляцию в реальную
  функцию. Возможность не удалена; новый live-сценарий не заявляется.

Вспомогательные браузерные компоненты оставлены: на них есть зависимости.
Нормальный Gateway-сценарий не требует установки Playwright.

## Что осталось только у разработчика

Все docs, tests, CI, инструменты сборки/диагностики, исторические отчёты,
журналы, данные и рабочая .venv. ACCEPTANCE.md и три дублирующих BAT-ярлыка
сохранены в проекте; в ZIP их заменяют README и общий start.bat.
Архив содержит tools/mock_demo.py для офлайн-проверки у заказчика.
Действующий account.toml не копируется: в ZIP создаётся пустой образец.

## Форма поставки

Windows/macOS: 97 файлов; Linux: 96. Полный состав указан ниже.
Архивы и распакованные чистые папки находятся в Downloads/Sarex-Loader-rc7.
Ничего не опубликовано в GitHub Releases этим этапом.
README содержит установку, команды, вопросы, файлы результатов и ограничения.

## Проверки

- 53 целевые проверки состава, запуска, конфигурации и команд пройдены.
- Ruff src/tests/tools/start.py: без замечаний.
- Чистая установка macOS ZIP в новый временный каталог: справка и проверки
  отсутствия согласия load пройдены, настройки и Sarex не меняются.
- Mock-upload из установленного сокращённого ZIP: 1 создание, 2 пропуска
  дубликатов, 0 POST при повторе, 0 запросов Sarex.
- Полный pytest: **2457 passed, 8 skipped, 103 subtests passed**, 192,92 с.
  Все 8 пропусков требуют настоящей Windows; ошибок нет.
  Лог: outputs/customer-rc7-validation/pytest.txt.

Предыдущий Windows CI run 42071042260, commit 02dc3bc, прошёл нативные проверки.
MacOS job тогда не получила runner; отдельная локальная сверка platform.json
совпала с Windows. **Новый архив rc.7 пока не запускался на Windows** — для него
добавлена проверка состава в workflow. Linux и Windows ARM нативно не проверены.

## До передачи заказчику

1. Windows/macOS workflow и compare на коммите с rc.7, затем использовать его ZIP.
2. На компьютере сестры: -help и офлайн-тест, без аккаунта и клиентских данных.
3. Авторизованный preview и fill на копии Excel — после сверки правил/результатов.
4. Реальный 99-Тест — только с отдельным разрешением; рабочая загрузка — после
   подтверждения плана. Никаких таких отправок в этом этапе нет.
5. Создание папок остаётся отдельным незавершённым live-сценарием.

## Инвентаризация всех модулей

| Модуль | В клиентском ZIP | Назначение из исходника |
|---|---|---|
| `__init__.py` | Да | Local registry audits: no network, credentials or business-data writes. |
| `__main__.py` | Да |  |
| `acceptance_scope.py` | Да | One reviewed two-document acceptance manifest; never a production write scope. |
| `acceptance_upload.py` | Да | Explicit, immutable two-PDF acceptance exercise through the current loader. |
| `api_client.py` | Да | Isolated Documentation client. Supplemental POST methods require explicit mock opt-in. |
| `api_models.py` | Да | Minimal typed projection of Documentation Document, with explicit local invariants. |
| `api_transport.py` | Да | Trusted offline transport boundary. No socket adapter or HTTP dependency in stage 4. |
| `api_upload_models.py` | Да | Postman request fields and defensive response projections, not inferred server schemas. |
| `api_workflow.py` | Нет, инструмент разработчика | One PDF mock workflow, with in-memory checkpoints only. Not a production uploader. |
| `audit.py` | Да | Read-only inspection registry validation. No matching of PDFs or remote documents. |
| `auth.py` | Да | Explicit token issuance/refresh, no credential discovery or token persistence. |
| `browser_extension.py` | Да | Bounded stdio client for the official Playwright MCP, not a Sarex API client. |
| `browser_tree.py` | Да | Read Gateway responses generated by Sarex UI; never extract or replay credentials. |
| `bundle_diagnostics.py` | Да | CREATE_BUNDLE structure and a narrowly bounded status observation, never raw bodies. |
| `children.py` | Нет, инструмент разработчика | Bounded display of a validated Document response, without traversal or I/O. |
| `cli.py` | Да | Local workflows and explicitly confirmed integration with the closed single-test. |
| `config.py` | Да | Explicit local configuration only. No environment or credential discovery. |
| `confirmed_absences.py` | Да | Customer's manual observations, not permanent assertions of remote absence. |
| `console.py` | Да | Consistent Unicode output for terminals, redirected output and Windows CI. |
| `cooperative_stop.py` | Да | Ctrl+C requests a safe boundary; it must never raise inside a write phase. |
| `customer.py` | Да | One small path configuration for both scripts; no machine-specific paths or secrets. |
| `customer_launcher.py` | Да | Short Russian console commands. Working runs never combine SK and VK. |
| `customer_start.py` | Да | Small launch menu; all inspection work remains in the existing customer CLI. |
| `customer_test.py` | Да | Customer command: one stable synthetic document, preview first, explicit plan consent. |
| `customer_test_scope.py` | Да | Persistent one-document customer test; never a reset mechanism for old operations. |
| `excel_commit.py` | Да | Backup and atomic URL-only replacement. No network or remote journal transitions. |
| `excel_copy.py` | Да | Patch only empty URL cells in a bounded XLSX snapshot, retaining other ZIP members. |
| `excel_io.py` | Да | Bounded OOXML preflight and read-only workbook access; never execute external content. |
| `file_safety.py` | Да | POSIX descriptor-based access; do not follow links in any path component. |
| `folder_creation.py` | Да | Isolated, durable mock acceptance workflow. No production CLI dispatch exists. |
| `folder_resolver.py` | Да | Explicit paths and a shared, exact Gateway hierarchy index. Never creates folders. |
| `gateway_check.py` | Нет, инструмент разработчика | Repeatable read-only sample/full route check; no PDF bytes, SQLite or upload imports. |
| `gateway_checkpoint.py` | Да | Append-only metadata checkpoints, separate from upload SQLite and credentials. |
| `gateway_client.py` | Нет, инструмент разработчика | Gateway client restricted to an explicit synthetic two-header mock contract. |
| `gateway_compare.py` | Нет, инструмент разработчика | Bounded GET comparison. Agreement is evidence, never a completeness contract. |
| `gateway_diagnostic.py` | Нет, инструмент разработчика | One access-only Gateway GET; hypothesis, never a discovery or authentication fallback. |
| `gateway_diagnostic_metadata.py` | Да | Closed projection of untrusted response headers; no response bodies or arbitrary text. |
| `gateway_diagnostic_policy.py` | Да | User-supplied exact Gateway route, for one access-only hypothesis test. |
| `gateway_import.py` | Да | Offline script-2 candidates from a bounded Gateway snapshot. No HTTP or XLSX writes. |
| `gateway_mock_transport.py` | Да | In-memory Gateway simulation only. The synthetic URL is NOT a Sarex endpoint. |
| `gateway_models.py` | Да | Offline Gateway response projection. No endpoints, transport, logging or file access. |
| `gateway_read_only.py` | Нет, инструмент разработчика | Safe preview only until the real Gateway route and Identity contract are confirmed. |
| `gateway_retry.py` | Да | Bounded retries for metadata GET only, with pacing and safe Retry-After handling. |
| `gateway_summary.py` | Нет, инструмент разработчика | Fixed-scope, name-free summary of an already parsed Gateway response. |
| `gateway_tree.py` | Да | Fresh selective metadata reads using the existing Documentations authentication. |
| `gateway_tree_policy.py` | Да | One exact metadata GET on the disk verified by the bounded live probe. |
| `https_transport.py` | Да | Explicitly armed HTTPS reads + token issuance only; no redirects/proxies/retries. |
| `journal.py` | Да | Private SQLite checkpoints for POSIX and Windows; no network authorization. |
| `live_upload.py` | Нет, инструмент разработчика | Legacy preparation entrypoint; never silently upgrade its confirmation to real writes. |
| `local_moves.py` | Да | Only proven Excel misses may move; native no-replace rename, never copy/delete. |
| `matching.py` | Да | Expected linear-time exact matching, with shared candidate and collision tables. |
| `messages.py` | Да | Russian presentation; machine codes remain stable and never contain secrets. |
| `monthly_folders.py` | Да | Conservative per-parent calendar naming. Pure planning, no HTTP or mutation. |
| `multipart.py` | Да | Single-use multipart/form-data PDF stream. No network, no source mutations. |
| `name_check.py` | Да | Local, literal name checks. No I/O, URL construction, normalization or logging. |
| `pdf_route_guard.py` | Да | Veto contradictory filename/Excel evidence; never route by a guessed filename. |
| `pdf_scan.py` | Да | One flat directory pass; bounded streaming fingerprints, no PDF interpretation. |
| `pipeline.py` | Да | Audit/matching/target plan with optional read-only tree discovery; no uploader. |
| `process_lock.py` | Да | Nonblocking advisory locks; closing the fd releases the process lock. |
| `production_scope.py` | Да | Explicit SK/VK upload scope, separate from every historical 99-Test exception. |
| `production_upload.py` | Да | Customer upload: reviewed fresh routes, permanent intents and the shared uploader. |
| `profile_auth.py` | Да | Explicit, locally configured login; only token issuance may use POST. |
| `profile_workflow.py` | Да | Customer boundary: one profile, one workbook, one flat PDF directory, one fresh tree. |
| `read_only_api.py` | Нет, инструмент разработчика | Separate manual entry point. Preview by default; no link to upload/fill-urls. |
| `read_only_policy.py` | Да | Closed production read-only scope; configuration cannot add hosts or write routes. |
| `recovery.py` | Да | Multi-export local URL recovery: exact contextual index, reviewed copy, no API imports. |
| `recovery_config.py` | Да | Explicit recovery scope: local exports or opt-in tree reads; no credentials. |
| `recursive_gateway.py` | Да | Visit every observed folder of ONE selected root. No inference from Excel paths. |
| `reports.py` | Да | Publish private JSON/Markdown to a fresh separate directory, never overwrite. |
| `response_candidates.py` | Да | Minimal identifiers for reconciliation, never proof of API success or ownership. |
| `response_shape.py` | Да | Safe structural diagnostics: fixed field names/types/reasons only, never response values. |
| `run_results.py` | Да | One customer report directory; archive only this run's successful diagnostics. |
| `russian_reports.py` | Да | Human-readable recovery sidecars, without modifying customer Excel schemas. |
| `safe_logging.py` | Да | Allowlisted events: never format user values, exceptions or arbitrary objects. |
| `safety.py` | Да | Fail-closed execution policy; this stage has no execution override. |
| `single_test.py` | Да | Manual single synthetic upload, fixed scope, fixed durable journal, preview by default. |
| `single_test_config.py` | Да | Explicit Bundle fields; target/disk/source bytes cannot be overridden by configuration. |
| `single_test_diagnostic.py` | Да | One auth POST and three fixed GETs; never opens or modifies the upload journal. |
| `single_test_identity.py` | Да | Closed set of explicitly authorized tests, not a factory for retry identities. |
| `single_test_predecessor.py` | Да | Read-only evidence for historical attempts; never resolves their UNKNOWN states. |
| `single_test_prepare.py` | Да | Local-only preparation of the single authorized independent test. |
| `single_test_scope.py` | Да | User-confirmed Documentation disk and DevTools path for ONE test target. |
| `single_test_trace.py` | Да | Single-test stage diagnostics: static codes and structural metadata, never raw errors. |
| `single_test_transport.py` | Да | One-purpose HTTPS adapter: fixed test target, fixed PDF, durable intent and ordered requests. |
| `synthetic_pdf.py` | Да | One fixed valid tiny PDF. No caller-supplied paths, content, images or filenames. |
| `target_diagnostics.py` | Нет, инструмент разработчика | Read-only metadata diagnosis. No raw fields, paths, names or inferred disk inheritance. |
| `target_response_trace.py` | Нет, инструмент разработчика | Opt-in safe per-stage diagnostics. Never retry or reinterpret a rejected response. |
| `test_disk_config.py` | Нет, инструмент разработчика | Fixed, non-secret test-disk configuration. A saved ID never authorizes resource writes. |
| `test_target.py` | Да | Fail-closed ancestry evidence using Document.folders edges, not names or guessed path syntax. |
| `test_target_check.py` | Нет, инструмент разработчика | Manual test-folder preflight: one token POST, three exact GETs, zero resource writes. |
| `test_target_policy.py` | Да | Fixed read scope for the customer-authorized test branch. No resource write routes. |
| `token_response_diagnostic.py` | Нет, инструмент разработчика | Opt-in token response field inspection: one POST, no session tokens or subsequent GET. |
| `tree_acceptance.py` | Да | User-accepted operational evidence; never an official completeness guarantee. |
| `tree_source.py` | Да | Shared bounded tree sources: private JSON exports or opt-in browser reads. |
| `types_validation.py` | Да | Shared types-response validation; diagnostics contain fixed labels and types only. |
| `upload_mock.py` | Да | Deterministic offline server fixture for the upload command; NEVER a Sarex adapter. |
| `upload_preview.py` | Да | All-file, multi-directory upload preview using existing audit, matching and resolver. |
| `upload_workflow.py` | Да | Script 1: local plan, offline simulation or the closed single-test, and a new XLSX. |
| `user_settings.py` | Да | Local or explicitly distributed account. Secrets never enter plans or reports. |
| `windows_files.py` | Да | Native Windows customer read/report primitives; no WSL and no reparse traversal. |
| `windows_journal.py` | Да | Windows filesystem guards for Journal; the SQLite schema/state machine stay shared. |
| `windows_journal_api.py` | Да | Small native Win32 boundary for the private SQLite upload ledger. |
