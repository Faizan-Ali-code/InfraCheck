@echo off
REM Creates or updates the virtual environment in .venv (called by run.bat).
REM Reinstalls only when requirements.txt changed since the last successful install.
setlocal
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    fc /b "requirements.txt" ".venv\installed-requirements.txt" >nul 2>&1 && exit /b 0
)

set "PY="
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1 && set "PY=py -3"
if not defined PY (
    python -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1 && set "PY=python"
)
if not defined PY (
    echo ERROR: InfraCheck needs Python 3.11 or newer: https://www.python.org/downloads/
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment in .venv ...
    %PY% -m venv .venv || exit /b 1
)
echo Installing requirements ...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt || exit /b 1
copy /y "requirements.txt" ".venv\installed-requirements.txt" >nul
exit /b 0
