"""Small launch menu; all inspection work remains in the existing customer CLI."""

import sys

from sarex_loader import customer_launcher
from sarex_loader.console import configure_console
from sarex_loader.safety import ValidationError
from sarex_loader.user_settings import settings_configured, settings_path

MENU = '''Sarex Loader
1 — Проверить PDF СК (без загрузки)
2 — Проверить PDF ВК (без загрузки)
3 — Восстановить URL в Excel СК (с резервной копией)
4 — Восстановить URL в Excel ВК (с резервной копией)
5 — Изменить логин и пароль
6 — Справка
7 — Подготовить тестовый PDF для 99-Тест (без отправки)
0 — Выход
Производственная загрузка PDF и создание папок выключены.
'''
COMMANDS = {'1': ['-preview', 'sk'], '2': ['-preview', 'vk'],
            '3': ['-fill', 'sk'], '4': ['-fill', 'vk'], '5': ['-setup'], '6': ['-help'],
            '7': ['-test-pdf']}


def main(argv=None, *, ask=input):
    configure_console()
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if not argv:
            print(MENU)
            while True:
                choice = ask('Выберите действие: ').strip()
                if choice == '0':
                    return 0
                if choice in COMMANDS:
                    argv = COMMANDS[choice]
                    break
                print('Введите число от 0 до 7.')
        if argv in (['-preview'], ['-fill']):
            while True:
                profile = ask('Реестр: 1 — СК, 2 — ВК: ').strip().casefold()
                if profile in {'1', '2', 'sk', 'vk', 'ск', 'вк'}:
                    argv = [*argv, 'sk' if profile in {'1', 'sk', 'ск'} else 'vk']
                    break
                print('Выберите СК или ВК.')
        if ((argv[:1] == ['-test-pdf'] or len(argv) >= 2
             and argv[0] in {'-preview', '-fill'} and argv[1] in {'sk', 'vk'})
                and not settings_configured(settings_path())):
            print('Первый запуск: укажите учётную запись Sarex. Настройки сохранятся локально.')
            result = customer_launcher.main(['-setup'])
            if result:
                return result
        return customer_launcher.main(argv)
    except (EOFError, KeyboardInterrupt):
        print('Запуск отменён. Входные документы не изменялись.')
        return 130
    except (OSError, ValidationError):
        print('Не удалось прочитать локальные настройки. Проверьте доступ к папке пользователя.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
