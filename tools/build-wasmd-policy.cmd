@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0build-wasmd-policy.ps1" %*
exit /b %errorlevel%
