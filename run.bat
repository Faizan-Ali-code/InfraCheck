@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo First run: creating virtual environment, please wait...
    python -m venv .venv || goto :error
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt || goto :error
)
echo Initializing InfraChecker. Please wait...
".venv\Scripts\python.exe" -m infrachecker %*
pause
exit /b
:error
echo Setup failed. Make sure Python 3.12 is installed and on PATH.
pause
