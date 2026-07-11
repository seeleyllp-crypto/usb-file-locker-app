@echo off
cd /d "%~dp0"
call "%~dp0Ensure Dependencies.cmd"
if errorlevel 1 (
  echo.
  echo USB File Locker could not start because setup failed.
  pause
  exit /b 1
)
%PYTHON_CMD% "usb_file_locker.py"
pause
