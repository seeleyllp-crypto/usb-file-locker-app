@echo off
cd /d "%~dp0"
call "%~dp0Ensure Dependencies.cmd"
if errorlevel 1 (
  echo.
  echo Audit Log Viewer could not start because setup failed.
  pause
  exit /b 1
)
%PYTHON_CMD% "audit_log_viewer.py"
pause
