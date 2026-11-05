"""One customer report directory; archive only this run's successful diagnostics."""

import os
import shutil
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from sarex_loader.config import checked_path, local_path
from sarex_loader.safety import ValidationError


def new_directory(base, protected):
    base = local_path(base) if base else Path.home() / 'Downloads'
    base = base.absolute()
    # Inspect existing ancestors before creating directories; never follow symlinks.
    existing = base
    while not existing.exists() and not existing.is_symlink():
        existing = existing.parent
    checked_path(existing, directory=True)
    if any(base.is_relative_to(p) for p in protected):
        raise ValidationError('Папка отчётов должна находиться отдельно от Excel и PDF.')
    base.mkdir(parents=True, exist_ok=True)
    checked_path(base, directory=True)
    name = datetime.now().strftime('отчет-%Y-%m-%d-%H-%M-%S')
    for suffix in range(1000):
        root = base / (name + (f'-{suffix}' if suffix else ''))
        if any(root.is_relative_to(p) or p.is_relative_to(root) for p in protected):
            raise ValidationError('Папка отчёта пересекается с исходными данными.')
        try:
            root.mkdir(mode=0o700)
            return root
        except FileExistsError:
            continue
    raise ValidationError('Не удалось выбрать новое имя папки отчёта.')


def pack_technical(technical, target):
    paths = sorted(technical.rglob('*'))
    for path in paths:
        checked_path(path, directory=path.is_dir())
    with ZipFile(target, 'x', compression=ZIP_DEFLATED) as archive:
        for path in paths:
            if path.is_file():
                archive.write(path, path.relative_to(technical).as_posix())
    with ZipFile(target) as archive:
        if archive.testzip() is not None:
            raise ValidationError('Не удалось проверить технический архив; исходники сохранены.')
    with target.open('rb') as stream:
        os.fsync(stream.fileno())
    if os.name != 'nt':
        from sarex_loader.file_safety import directory_fd

        with directory_fd(target.parent) as fd:
            os.fsync(fd)
    # Only a fresh, owned, completed run directory, never a resume source or upload journal.
    shutil.rmtree(technical)


def execute_with_reports(worker, command, profile, excel, root_url, results, settings,
                         *, pdf=None, no_move=False, resume=None):
    source = checked_path(local_path(excel), directory=False)
    if source.name.startswith('~$'):
        raise ValidationError('Выбран временный файл Excel (~$). Укажите сам реестр .xlsx.')
    protected = [source.parent]
    if pdf is not None:
        protected.append(checked_path(local_path(pdf), directory=True))
    root = new_directory(results or settings.results_dir, protected)
    technical = root / 'технические данные'
    technical.mkdir()
    log = root / 'журнал.txt'
    print('Начало проверки. Отчёты: ' + str(root))
    print('Подробный ход работы: ' + str(log))
    try:
        with (log.open('x', encoding='utf-8', buffering=1) as stream,
              redirect_stdout(stream), redirect_stderr(stream)):
            report = worker(command, profile, excel, root_url, technical, settings,
                            pdf=pdf, no_move=no_move, resume=resume)
        output = Path(report['output_directory'])
        visible = []
        for path in sorted(output.iterdir()):
            if path.suffix in ('.md', '.csv'):
                shutil.copyfile(path, root / path.name)
                visible.append(root / path.name)
        # Keep original Excel backups directly accessible; never put the only backup in ZIP.
        for backup in technical.glob('*-backups'):
            backup.rename(root / 'резервные копии Excel')
        summary = root / 'ИТОГИ.md'
        counts = report.get('counts', report.get('summary', {}))
        labels = {'total_pdf': 'Всего PDF', 'matched_excel': 'Сопоставлены с Excel',
                  'ready_to_upload': 'Разрешены к загрузке сейчас',
                  'ready_by_metadata': 'Подходят по метаданным',
                  'already_in_sarex': 'Уже есть в Sarex',
                  'requires_folder': 'Требуется месячная папка',
                  'missing_month_unconfirmed': 'Отсутствие месяца не подтверждено',
                  'date_conflicts': 'Конфликты дат', 'problem_files': 'Проблемные PDF',
                  'MATCHED': 'Однозначное совпадение', 'AMBIGUOUS': 'Неоднозначное совпадение',
                  'NOT_FOUND': 'Не найдено', 'SKIPPED': 'Пропущено',
                  'uploaded': 'Загружено PDF', 'urls_written': 'Записано URL',
                  'already_confirmed': 'Повторно проверено без загрузки'}
        lines = ['# Итоги ' + profile.upper(), '',
                 'Режим: ' + ('проверка PDF без загрузки' if command == 'preview'
                              else 'загрузка по подтверждённому плану' if command == 'load'
                              else 'восстановление URL в переданном Excel'), '',
                 '## Статистика', '',
                 *[f'- {labels.get(k, k)}: {v}' for k, v in counts.items()], '',
                 'Новых URL записано: ' + str(report.get('urls_written', 0)), '',
                 '## Подробные результаты', '']
        lines += [f'- [{p.name}]({p.name})' for p in sorted(
            visible, key=lambda p: (p.suffix != '.md', p.name))]
        lines += ['', 'Подробный ход работы: [журнал.txt](журнал.txt).',
                  'Технические данные и checkpoint: [технические-данные.zip]'
                  '(технические-данные.zip).',
                  ('Результаты отправок, пропусков и создания папок — в отчётах. '
                   'Создано папок: ' + str(sum(p['status'] == 'CREATED'
                                             for p in report.get('folders', []))) + '.'
                   if command == 'load' else 'Записи в Sarex и создание папок не выполнялись.'),
                  ('Запуск остановлен; журнал не сбрасывайте.' if report.get('stopped') else
                   'План отменён пользователем.' if report.get('cancelled') else ''), '']
        summary.write_text('\n'.join(lines), encoding='utf-8')
        pack_technical(technical, root / 'технические-данные.zip')
    except BaseException:
        with log.open('a', encoding='utf-8') as stream:
            stream.write('\nЗапуск не завершён. Технические данные сохранены без упаковки.\n')
        print('Запуск не завершён. Журнал и checkpoint сохранены: ' + str(root))
        raise
    report['output_directory'] = str(root)
    print('Готово. Сначала откройте: ' + str(summary))
    for path in sorted(visible, key=lambda p: (p.suffix != '.md', p.name)):
        print(('Отчёт: ' if path.suffix == '.md' else 'Подробная таблица: ') + str(path))
    if (root / 'резервные копии Excel').exists():
        print('Резервные копии Excel: ' + str(root / 'резервные копии Excel'))
    print('Журнал: ' + str(log))
    print('Для диагностики: ' + str(root / 'технические-данные.zip'))
    return report
