@echo off
setlocal
set "GIT_EXE=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\Git\cmd\git.exe"

if not exist "%GIT_EXE%" (
  echo Git was not found at:
  echo %GIT_EXE%
  pause
  exit /b 1
)

echo USB File Locker App GitHub Push
echo.
set /p REMOTE_URL=Paste your GitHub repo URL here: 

if "%REMOTE_URL%"=="" (
  echo No URL entered.
  pause
  exit /b 1
)

"%GIT_EXE%" remote get-url origin >nul 2>nul
if errorlevel 1 (
  "%GIT_EXE%" remote add origin "%REMOTE_URL%"
) else (
  "%GIT_EXE%" remote set-url origin "%REMOTE_URL%"
)

"%GIT_EXE%" push -u origin main
echo.
pause
