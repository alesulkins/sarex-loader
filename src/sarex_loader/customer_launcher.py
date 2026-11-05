"""Short Russian console commands. Working runs never combine SK and VK."""

import sys

from sarex_loader.config import checked_path, local_path
from sarex_loader.messages import describe
from sarex_loader.profile_workflow import run_profile
from sarex_loader.safety import ValidationError
from sarex_loader.user_settings import require_settings, root_id_from_url, setup

HELP = '''Sarex Loader — отдельный запуск для СК (sk) или ВК (vk).

sarex-loader -setup          Сохранить/изменить локальные логин и пароль.
sarex-loader -preview sk     Проверить Excel и PDF СК, прочитать всё дерево СК.
sarex-loader -preview vk     Проверить Excel и PDF ВК, прочитать всё дерево ВК.
sarex-loader -load sk        Загрузка СК: временно заблокирована.
sarex-loader -load vk        Загрузка ВК: временно заблокирована.
sarex-loader -load test DIR  Просмотр фиксированного теста двух PDF в 99-Тест.
sarex-loader -fill sk        Записать URL СК в переданный Excel с резервной копией.
sarex-loader -fill vk        Записать URL ВК в переданный Excel с резервной копией.
sarex-loader -test-pdf       Подготовить один тестовый PDF и проверить 99-Тест (GET).
sarex-loader -test-pdf --send SHA256  Отдельно подтвердить тестовую отправку.
sarex-loader -help           Эта справка.

Пути вводятся при запуске. -fill меняет только пустые URL в переданном Excel.
Корень СК: https://lk.sarex.io/documentations/2066367
Корень ВК: https://lk.sarex.io/documentations/2067117
Preview показывает план перемещения в «не найдено», но ничего не перемещает.
Подпапки PDF не обходятся. Содержимое PDF не меняется. Производственная запись запрещена.
Для диагностики: sarex-loader -preview sk (флаг --no-move сохранён для совместимости).
Продолжение прерванного обхода: добавьте --resume "путь к checkpoint".
Пример: sarex-loader -preview sk → Excel СК → папка PDF СК → ссылка СК → результаты.
'''


def ask_path(prompt, *, directory, ask=input):
    while True:
        value = ask(prompt).strip().strip('"')
        try:
            return checked_path(local_path(value), directory=directory)
        except ValidationError as exc:
            print(describe(str(exc)))


def collect_inputs(command, profile, *, ask=input):
    label = {'sk': 'СК', 'vk': 'ВК'}[profile]
    excel = ask_path(f'Полный локальный путь к Excel {label}: ', directory=False, ask=ask)
    pdf = (ask_path(f'Локальная папка PDF {label}: ', directory=True, ask=ask)
           if command == 'preview' else None)
    while True:
        root_url = ask(f'Ссылка на корневую папку {label} в Sarex: ').strip()
        try:
            root_id_from_url(profile, root_url)
            break
        except ValidationError as exc:
            print(str(exc))
    return {'excel': excel, 'pdf': pdf, 'root_url': root_url}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in ([], ['-help'], ['--help'], ['-h']):
        print(HELP)
        return 0
    try:
        if argv[:1] == ['-test-pdf']:
            from sarex_loader.customer_test import command as test_command

            return test_command(argv[1:])
        if argv[:2] == ['-load', 'test']:
            from sarex_loader.acceptance_upload import command

            return command(argv[2:])
        if argv == ['-setup']:
            setup()
            return 0
        options = {}
        if '--no-move' in argv:
            argv.remove('--no-move')
            options['no_move'] = True
        if '--resume' in argv:
            position = argv.index('--resume')
            if position + 1 >= len(argv):
                raise ValidationError('После --resume нужен путь к checkpoint.')
            options['resume'] = argv.pop(position + 1)
            argv.pop(position)
        if (len(argv) != 2 or argv[0] not in ('-preview', '-load', '-fill')
                or argv[1] not in ('sk', 'vk')):
            raise ValidationError('Неизвестная команда или профиль. Выполните sarex-loader -help.')
        command, profile = argv[0][1:], argv[1]
        if command == 'load':
            raise ValidationError('Реальная загрузка временно заблокирована. '
                                  'Никакие запросы не отправлены. Используйте -preview ' + profile)
        settings = require_settings()
        inputs = collect_inputs(command, profile)
        run_profile(command, profile, results=settings.results_dir,
                    settings=settings, **inputs, **options)
        return 0
    except (EOFError, KeyboardInterrupt):
        print('Работа прервана. Сохранённые журналы и файлы не удаляйте.')
        return 130
    except (ValidationError, OSError) as exc:
        print('Ошибка: ' + (describe(str(exc)) if isinstance(exc, ValidationError)
                            else 'Не удалось прочитать или сохранить локальные файлы.'))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
