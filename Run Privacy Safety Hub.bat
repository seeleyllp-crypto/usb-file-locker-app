@echo off
cd /d "%~dp0"
call "%~dp0Ensure Dependencies.cmd"
if errorlevel 1 (
  echo.
  echo Privacy Safety Hub could not start because setup failed.
  pause
  exit /b 1
)
%PYTHON_CMD% "privacy_safety_hub.py"
pause
