@echo off
setlocal
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
chcp 65001 >nul
where py >nul 2>nul
if not errorlevel 1 (
    py -3 "%~dp0start.py" %*
) else (
    where python >nul 2>nul
    if errorlevel 1 (
        echo Не найден Python. Установите Python 3.11 или новее с python.org и повторите запуск.
        pause
        exit /b 2
    )
    python "%~dp0start.py" %*
)
set SAREX_EXIT=%errorlevel%
pause
exit /b %SAREX_EXIT%
