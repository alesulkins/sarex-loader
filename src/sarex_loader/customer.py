"""One small path configuration for both scripts; no machine-specific paths or secrets."""

import tomllib
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

from sarex_loader.api_models import valid_id
from sarex_loader.config import checked_path, local_path
from sarex_loader.file_safety import read_snapshot
from sarex_loader.monthly_folders import month_number
from sarex_loader.recovery_config import parse_recovery_config
from sarex_loader.safety import ValidationError


def load_job(path, *, require_pdf=True):
    path = checked_path(local_path(path), directory=False)
    try:
        data = tomllib.loads(read_snapshot(path, 65536).decode('utf-8'))
        if data.keys() - {'routes', 'paths', 'confirmed_missing'}:
            raise ValueError
        paths = data['paths']
        if set(paths) != {'excel_sk', 'excel_vk', 'pdf_sk', 'pdf_vk', 'results'}:
            raise ValueError

        def absolute(value):
            result = local_path(value)
            return result if result.is_absolute() else path.parent / result

        excel = {kind: checked_path(absolute(paths['excel_' + kind]), directory=False)
                 for kind in ('sk', 'vk')}
        pdf = {}
        for kind in ('sk', 'vk'):
            values = paths['pdf_' + kind]
            if not isinstance(values, list) or not 1 <= len(values) <= 128:
                raise ValueError
            pdf[kind] = [checked_path(absolute(v), directory=True) if require_pdf else absolute(v)
                         for v in values]
        results = checked_path(absolute(paths['results']), directory=True)
        protected = [*(p.parent for p in excel.values()),
                     *(p for roots in pdf.values() for p in roots)]
        if any(results.is_relative_to(p) or p.is_relative_to(results) for p in protected):
            raise ValidationError('Папка результатов должна быть отдельно от Excel и PDF.')
        route_path = checked_path(absolute(data['routes']), directory=False)
        routing = tomllib.loads(read_snapshot(route_path, 65536).decode('utf-8'))
        # Each selected workbook has its own explicit input scope (also across Windows drives).
        configs = []
        for registry in routing['registries']:
            kind = registry['inspection_type']
            one = deepcopy(routing)
            one['input_root'] = str(excel[kind].parent)
            one['registries'] = [{**registry, 'excel': str(excel[kind])}]
            one['filename_numbers'] = {kind: routing.get('filename_numbers', {}).get(kind, {})}
            configs.append(parse_recovery_config(one))
        config = replace(configs[0], registries=tuple(c.registries[0] for c in configs),
                         routes={k: v for c in configs for k, v in c.routes.items()},
                         numbers={k: v for c in configs for k, v in c.numbers.items()})
        if config.tree is None or config.tree.source != 'gateway':
            raise ValueError
        confirmed = set()
        for item in data.get('confirmed_missing', []):
            if (set(item) != {'parent_id', 'months', 'evidence'}
                    or not valid_id(item['parent_id']) or not item['evidence']
                    or not isinstance(item['months'], list)):
                raise ValueError
            for month in item['months']:
                month_number(month)
                confirmed.add((item['parent_id'], month))
        return config, pdf, results, confirmed
    except ValidationError:
        raise
    except (ValueError, KeyError, TypeError):
        raise ValidationError(
            'Проверьте файл запуска: пути, реестры и подтверждения месяцев.') from None


def run_customer(command, path, *, write_copy=False, expected_plan=None):
    config, pdf, results, confirmed = load_job(path, require_pdf=command == 'upload')
    output = results / (command + '-' + datetime.now(UTC).strftime('%Y%m%dT%H%M%S')
                        + '-' + uuid4().hex[:8])
    print('Начало проверки. Используются текущая учётная запись и свежие метаданные Sarex.')
    if command == 'upload':
        from sarex_loader.upload_preview import run_full_preview

        if write_copy or expected_plan:
            raise ValidationError('Загрузка в этом режиме только моделируется; запись запрещена.')
        report = run_full_preview(config, pdf, output, confirmed_missing=confirmed)
        print(f"Проверено PDF: {report['counts']['total_pdf']}. "
              'Создание папок и загрузка не выполнялись.')
    else:
        from sarex_loader.recovery import run_recovery

        report = run_recovery(config, output_dir=output, read_tree=True,
                              write_copy=write_copy, expected_plan_sha256=expected_plan)
        print('Восстановление ссылок завершено. Исходные Excel не изменены.')
    report['output_directory'] = str(output)
    print('Результаты сохранены: ' + str(output))
    return report
