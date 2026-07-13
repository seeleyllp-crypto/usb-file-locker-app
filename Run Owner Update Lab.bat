@echo off
cd /d "%~dp0"
call "%~dp0Ensure Dependencies.cmd"
if errorlevel 1 (
  echo.
  echo Owner Update Lab could not start because setup failed.
  pause
  exit /b 1
)
%PYTHON_CMD% "owner_update_lab.py"
pause
