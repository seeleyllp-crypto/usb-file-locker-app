@echo off
cd /d "%~dp0"
call "%~dp0Ensure Dependencies.cmd"
if errorlevel 1 (
  echo.
  echo Recovery Kit Builder could not start because setup failed.
  pause
  exit /b 1
)
%PYTHON_CMD% "recovery_kit_builder.py"
pause
