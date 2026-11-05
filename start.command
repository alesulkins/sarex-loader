#!/bin/sh
cd "$(dirname "$0")" || exit 2
export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8
if command -v python3 >/dev/null 2>&1; then
    python3 ./start.py "$@"
    sarex_exit=$?
else
    echo 'Не найден Python. Установите Python 3.11 или новее с python.org и повторите запуск.'
    sarex_exit=2
fi
printf '\nНажмите Enter для закрытия окна…'
read -r sarex_answer
exit "$sarex_exit"
