@echo off
cd /d "%~dp0"
call "%~dp0Ensure Dependencies.cmd"
if errorlevel 1 (
  echo.
  echo PERM UNLOCK Workbench could not start because setup failed.
  pause
  exit /b 1
)
%PYTHON_CMD% "perm_unlock_workbench.py"
pause
