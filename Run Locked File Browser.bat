@echo off
cd /d "%~dp0"
call "%~dp0Ensure Dependencies.cmd"
if errorlevel 1 (
  echo.
  echo Locked File Browser could not start because setup failed.
  pause
  exit /b 1
)
%PYTHON_CMD% "locked_file_browser.py"
pause
