@echo off
call "%~dp0start.bat" -setup %*
exit /b %errorlevel%
