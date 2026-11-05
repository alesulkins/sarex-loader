@echo off
setlocal
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
chcp 65001 >nul
if exist "%~dp0.venv\Scripts\python.exe" goto local_python
where python >nul 2>nul
if not errorlevel 1 goto path_python
where py >nul 2>nul
if not errorlevel 1 goto py_launcher
echo Не найден Python. Установите Python 3.11 или новее с python.org и повторите запуск.
set SAREX_EXIT=2
goto finish
:local_python
"%~dp0.venv\Scripts\python.exe" "%~dp0start.py" %*
goto completed
:path_python
python "%~dp0start.py" %*
goto completed
:py_launcher
py -3 "%~dp0start.py" %*
:completed
set SAREX_EXIT=%errorlevel%
:finish
if "%~1"=="" pause
exit /b %SAREX_EXIT%
