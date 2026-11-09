@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_local.ps1"
if errorlevel 1 (
  echo.
  echo Pyramid Recon could not start. Read the error above.
  pause
)
