@echo off
cd /d "%~dp0"
call "%~dp0Ensure Dependencies.cmd"
if errorlevel 1 (
  echo.
  echo Download Verification Center could not start because setup failed.
  pause
  exit /b 1
)
%PYTHON_CMD% "download_verification_center.py"
pause
