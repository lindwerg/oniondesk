@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Install Python 3.10 or newer: https://www.python.org/downloads/
  pause
  exit /b 1
)
py -3 -c "import sys; assert sys.version_info >= (3,10), 'Python 3.10+ is required'"
if errorlevel 1 (pause & exit /b 1)
py -3 -m venv .venv
if errorlevel 1 (pause & exit /b 1)
.venv\Scripts\python.exe -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 (pause & exit /b 1)
.venv\Scripts\python.exe start_app.py
if errorlevel 1 pause
