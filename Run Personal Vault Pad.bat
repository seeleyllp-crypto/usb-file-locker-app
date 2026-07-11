@echo off
cd /d "%~dp0"
call "%~dp0Ensure Dependencies.cmd"
if errorlevel 1 (
  echo.
  echo Personal Vault Pad could not start because setup failed.
  pause
  exit /b 1
)
%PYTHON_CMD% "personal_vault_pad.py"
pause
