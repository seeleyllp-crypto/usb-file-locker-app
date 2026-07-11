@echo off
cd /d "%~dp0"
call "%~dp0Ensure Dependencies.cmd"
if errorlevel 1 (
  echo.
  echo Text Log Processor could not start because setup failed.
  pause
  exit /b 1
)
%PYTHON_CMD% "text_log_processor.py"
pause
