@echo off
set "PYTHON_CMD="

where python >nul 2>&1
if not errorlevel 1 set "PYTHON_CMD=python"

if not defined PYTHON_CMD (
  where py >nul 2>&1
  if not errorlevel 1 set "PYTHON_CMD=py -3"
)

if not defined PYTHON_CMD (
  echo Python 3 was not found.
  echo Install Python 3 from https://www.python.org/downloads/windows/
  exit /b 1
)

%PYTHON_CMD% -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
if errorlevel 1 (
  echo Python 3.9 or newer is required.
  exit /b 1
)

%PYTHON_CMD% -c "import cryptography" >nul 2>&1
if not errorlevel 1 exit /b 0

echo.
echo First-time setup: installing the required cryptography package...
echo This can take a minute and requires an internet connection.

%PYTHON_CMD% -m pip --version >nul 2>&1
if errorlevel 1 %PYTHON_CMD% -m ensurepip --upgrade
if errorlevel 1 (
  echo Could not set up pip for this Python installation.
  exit /b 1
)

%PYTHON_CMD% -m pip install --disable-pip-version-check -r "%~dp0requirements.txt"
if errorlevel 1 (
  echo Normal installation failed. Trying a per-user installation...
  %PYTHON_CMD% -m pip install --user --disable-pip-version-check -r "%~dp0requirements.txt"
)
if errorlevel 1 (
  echo.
  echo Could not install cryptography. Check the internet connection and try again.
  exit /b 1
)

%PYTHON_CMD% -c "import cryptography" >nul 2>&1
if errorlevel 1 (
  echo cryptography installed, but Python still cannot import it.
  exit /b 1
)

echo Setup complete.
exit /b 0

