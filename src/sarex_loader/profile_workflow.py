"""Customer boundary: one profile, one workbook, one flat PDF directory, one fresh tree."""

import hashlib
import json
import time
import tomllib
from datetime import UTC, datetime
from importlib.resources import files
from uuid import uuid4

from sarex_loader.config import checked_path, local_path
from sarex_loader.gateway_checkpoint import GatewayCheckpoint
from sarex_loader.profile_auth import use_settings
from sarex_loader.recovery_config import parse_recovery_config
from sarex_loader.reports import _write_bundle
from sarex_loader.safety import ValidationError
from sarex_loader.tree_source import read_tree, snapshot_payloads, tree_snapshot, tree_summary
from sarex_loader.user_settings import root_id_from_url


def profile_config(profile, excel, root_url):
    root_id = root_id_from_url(profile, root_url)
    excel = checked_path(local_path(excel), directory=False)
    data = tomllib.loads(files('sarex_loader').joinpath('profile-routes.toml').read_text('utf-8'))
    data['registries'] = [{**r, 'excel': str(excel)} for r in data['registries']
                          if r['inspection_type'] == profile]
    if (len(data['registries']) != 1
            or data['registries'][0]['root_id'] != str(root_id)):
        raise ValidationError('Профиль и правила корневой папки не согласованы.')
    data['input_root'] = str(excel.parent)
    data['filename_numbers'] = {profile: data.get('filename_numbers', {}).get(profile, {})}
    data['tree'].update(root_ids=[root_id], traversal='recursive', max_folders=2000)
    return parse_recovery_config(data)


def _run_profile(command, profile, excel, root_url, results, settings, *, pdf=None,
                no_move=False, resume=None):
    if command not in ('preview', 'fill', 'load'):
        raise ValidationError('Неизвестная команда.')
    config = profile_config(profile, excel, root_url)
    results = checked_path(local_path(results), directory=True)
    protected = [config.root]
    if command in ('preview', 'load'):
        pdf = checked_path(local_path(pdf), directory=True)
        protected.append(pdf)
    elif pdf is not None:
        raise ValidationError('Восстановление ссылок не принимает каталог PDF.')
    if any(results.is_relative_to(p) or p.is_relative_to(results) for p in protected):
        raise ValidationError('Папка результатов должна находиться отдельно от Excel и PDF.')
    prefix = (command + '-' + profile + '-' + datetime.now(UTC).strftime('%Y%m%dT%H%M%S')
              + '-' + uuid4().hex[:8])
    print('Авторизация Sarex из локальной конфигурации. Секреты не записываются в отчёты.')
    print('Рекурсивное чтение выбранного раздела ' + profile.upper()
          .replace('SK', 'СК').replace('VK', 'ВК') + '.')
    checkpoint_path = local_path(resume) if resume else results / (prefix + '-checkpoint')
    principal = hashlib.sha256(settings.username.encode('utf-8')).hexdigest()
    last = 0
    def progress(done, pending, objects):
        nonlocal last
        if time.monotonic() - last >= 20:
            print(f'Прочитано папок: {done}; ожидают: {pending}; объектов: {objects}.', flush=True)
            last = time.monotonic()
    print('Checkpoint для продолжения прерванного обхода: ' + str(checkpoint_path))
    with use_settings(settings), GatewayCheckpoint(
            checkpoint_path, config.tree, principal, protected, resume=bool(resume)) as checkpoint:
        index = read_tree(config.tree, set(), allow_browser=True,
                          checkpoint=checkpoint, progress=progress)
    tree = tree_summary(config.tree, index)
    cache = snapshot_payloads(tree_snapshot(config.tree, index), config.tree.max_response_bytes)
    cache['tree-diagnostics.json'] = json.dumps(tree, ensure_ascii=False, indent=2).encode()
    cache_path = results / (prefix + '-tree')
    _write_bundle(cache_path, cache, protected)
    print(index.observation['completeness_description'])
    print(f"Прочитано папок: {len(index.queried_folders)}; "
          f"GET: {index.refresh_metrics['get_attempts']}. Снимок: {cache_path}")
    print(f"PDF: {index.refresh_metrics['pdf_documents']}; "
          f"повторов GET: {index.refresh_metrics['get_retries']}; "
          f"неисследованных папок: {index.refresh_metrics['folders_unchecked']}.")
    if not index.observation['root_verified']:
        raise ValidationError('Корень не подтверждён сервером; обработка остановлена. '
                              'Диагностика сохранена: ' + str(cache_path))
    output = results / prefix
    if command in ('preview', 'load'):
        from sarex_loader.upload_preview import run_full_preview

        print('Проверка PDF верхнего уровня. Только план перемещения; '
              'исходные PDF остаются на месте.')
        preview_output = output if command == 'preview' else results / (prefix + '-preview')
        report = run_full_preview(config, {profile: [pdf]}, preview_output, flat=True,
                                  move_not_found=False, plan_moves=True, tree_index=index)
        if command == 'load':
            from sarex_loader.production_upload import run

            return run(config, index, report, pdf, config.registries[0].excel, output, settings,
                       no_move=no_move)
        print(f"Проверено PDF: {report['counts']['total_pdf']}. "
              f"Сопоставлено: {report['counts']['matched_excel']}. Загрузка запрещена.")
        for file in report['files']:
            if file['excel_candidates'] and not file['folder_id']:
                print(f"Для файла {file['filename']} не найдена папка назначения: "
                      f"{file['full_path'] or 'маршрут не определён'}. "
                      'Необходимо создать папку или проверить исходные данные.')
    else:
        from sarex_loader.recovery import run_recovery

        preview = run_recovery(config, read_tree=True, tree_index=index,
                               require_complete_children=True,
                               output_dir=results / (prefix + '-plan'))
        backup_dir = results / (prefix + '-backups')
        backup_dir.mkdir(mode=0o700)
        report = run_recovery(config, read_tree=True, tree_index=index, write_original=True,
                              backup_dir=backup_dir,
                              expected_plan_sha256=preview['plan_sha256'], output_dir=output,
                              require_complete_children=True)
        print(f"Записано новых URL в переданный Excel: {report['urls_written']}. "
              f'Заполненные URL сохранены. Резервные копии: {backup_dir}')
        pending = len(report['observed_candidates_pending_completeness'])
        if pending:
            print(f'Найдено кандидатов, ожидающих подтверждения полноты списка детей: {pending}. '
                  'Эти URL в копию не записаны.')
    print('Этот режим не создаёт папки Sarex. Результат: ' + str(output))
    report['output_directory'] = str(output)
    return report


def run_profile(command, profile, excel, root_url, results, settings, *, pdf=None,
                no_move=False, resume=None):
    from sarex_loader.run_results import execute_with_reports

    return execute_with_reports(_run_profile, command, profile, excel, root_url,
                                results, settings, pdf=pdf, no_move=no_move, resume=resume)
