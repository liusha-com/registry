@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0test-wasmd-component.ps1" %*
exit /b %errorlevel%
