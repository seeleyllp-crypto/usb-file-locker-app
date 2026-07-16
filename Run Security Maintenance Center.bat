@echo off
setlocal
call "%~dp0Ensure Dependencies.cmd"
if errorlevel 1 exit /b 1
"%PYTHON_CMD%" "%~dp0security_maintenance_center.py"
endlocal
