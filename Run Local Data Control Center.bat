@echo off
cd /d "%~dp0"
call "%~dp0Ensure Dependencies.cmd"
if errorlevel 1 (
  echo.
  echo Local Data Control Center could not start because setup failed.
  pause
  exit /b 1
)
%PYTHON_CMD% "local_data_control_center.py"
pause
