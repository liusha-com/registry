@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0test-wasmd-mode.ps1" %*
exit /b %errorlevel%
