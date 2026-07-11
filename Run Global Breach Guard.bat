@echo off
cd /d "%~dp0"
call "%~dp0Ensure Dependencies.cmd"
if errorlevel 1 (
  echo.
  echo Global Breach Guard could not start because setup failed.
  pause
  exit /b 1
)
%PYTHON_CMD% "global_breach_guard.py"
pause
