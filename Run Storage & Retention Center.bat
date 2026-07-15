@echo off
setlocal
call "%~dp0Ensure Dependencies.cmd"
if errorlevel 1 exit /b 1
"%PYTHON_CMD%" "%~dp0storage_retention_center.py"
endlocal
