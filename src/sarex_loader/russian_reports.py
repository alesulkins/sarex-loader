"""Human-readable recovery sidecars, without modifying customer Excel schemas."""

import csv
import io

from sarex_loader.messages import describe


def recovery_csv(report):
    summary = io.StringIO(newline='')
    writer = csv.writer(summary, delimiter=';', quoting=csv.QUOTE_ALL)
    writer.writerow(['Код', 'Описание', 'Количество строк'])
    for code, count in report['summary'].items():
        writer.writerow([code, describe(code), count])
    issues = io.StringIO(newline='')
    writer = csv.writer(issues, delimiter=';', quoting=csv.QUOTE_ALL)
    writer.writerow(['Реестр', 'Лист (номер)', 'Строка Excel', 'Статус', 'Причина'])
    for item in report.get('row_issues', []):
        kind = report['registries'][item['registry_index']]['inspection_type']
        writer.writerow([{'sk': 'СК', 'vk': 'ВК'}.get(kind, kind), item['sheet_index'],
                         item['row'], describe(item['status']), describe(item['reason'])])
    return {'recovery_summary.csv': summary.getvalue().encode('utf-8-sig'),
            'recovery_issues.csv': issues.getvalue().encode('utf-8-sig')}
