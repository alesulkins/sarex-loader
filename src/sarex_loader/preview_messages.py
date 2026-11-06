"""Contextual Russian diagnostics shared by preview CSV, Markdown and run log."""

from sarex_loader.messages import describe


def explain_file(file):
    messages = []
    candidates = file.get('excel_candidates', [])
    reasons = set(file.get('reasons', []))
    for row in candidates:
        for field, label in (('office', 'офис'), ('contractor', 'подрядчик'),
                             ('number', 'номер инспекции'), ('date', 'дата инспекции')):
            value = row.get(field)
            if value is None or isinstance(value, str) and not value.strip():
                messages.append(f"Строка Excel {row['row']}: не заполнен {label}. "
                                'Заполните поле в реестре; файл пропущен.')
    if len(candidates) > 1:
        rows = '; '.join(f"строка {r['row']}, дата {r.get('date') or 'не указана'}, "
                         f"офис {r.get('office') or 'не указан'}, "
                         f"подрядчик {r.get('contractor') or 'не указан'}" for r in candidates)
        messages.append('Номер не удалось однозначно сопоставить по дате PDF. '
                        'При одинаковых номере и дате выбор по офису или подрядчику '
                        'автоматически не выполняется. Кандидаты: ' + rows)
    for check in file.get('filename_route_checks', []):
        if 'excel_contractor' in check:
            hints = (check.get('filename_contractors', []) + check.get('filename_offices', [])
                     + check.get('filename_scopes', []))
            messages.append(f"Расхождение имени PDF и полей Excel, строка {check.get('row')}: "
                            f"в Excel офис «{check.get('excel_office')}», подрядчик "
                            f"«{check.get('excel_contractor')}»; в имени PDF: "
                            + ', '.join(hints) + '. Уточните исходные данные; файл пропущен. '
                            'Создание папки само по себе этот конфликт не устраняет.')
    for check in file.get('candidate_date_checks', []):
        messages.append(f"{describe(check['code'])}: строка Excel {check.get('row')}, "
                        f"дата Excel {check.get('excel_date')}, дата PDF {check.get('pdf_date')}. "
                        f"Предполагаемый путь по Excel: {file.get('full_path') or 'не определён'}.")
    if file.get('parent_id') and not file.get('folder_id'):
        if file.get('need_folder'):
            messages.append(f"Родительская папка существует (ID {file['parent_id']}). "
                            f"Отсутствует папка месяца {file.get('month')}: {file['full_path']}. "
                            'Добавьте папку месяца в указанную родительскую папку. '
                            'PDF не будет загружен до её появления и успешной повторной проверки.')
        else:
            messages.append('Месячная папка не найдена, но отсутствие не подтверждено: '
                            'необходимо получить полные метаданные родительской папки.')
    elif file.get('missing_component'):
        messages.append(f"Не найдена {file['missing_level']} «{file['missing_component']}»: "
                        f"{file.get('full_path')}. Проверьте данные Excel и добавьте "
                        'необходимую папку вручную, если маршрут подтверждён. '
                        'Программа создаёт только месяцы, не офисы и не подрядчиков.')
    # Keep every independent safety reason, even when a more specific explanation exists.
    messages.extend(describe(code) for code in [file.get('status'), *file.get('reasons', [])]
                    if code and not (code == 'EMPTY_REQUIRED' and messages))
    if 'ROUTE_NOT_CONFIGURED' in reasons and not file.get('full_path'):
        messages.append('Для сочетания офиса и подрядчика Excel нет подтверждённого маршрута. '
                        'Проверьте поля реестра и наличие соответствующей папки Sarex; '
                        'другая ветка автоматически не выбирается.')
    return '; '.join(dict.fromkeys(messages))
