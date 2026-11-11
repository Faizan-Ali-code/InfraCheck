@echo off
cd /d "%~dp0"
rem Setup runs until a pip install has completed for the current requirements.txt (copied as the marker).
fc /b requirements.txt ".venv\requirements.installed" >nul 2>&1 || call :setup || goto :error
echo Initializing InfraChecker. Please wait...
".venv\Scripts\python.exe" -m infrachecker %*
pause
exit /b

:setup
if not exist ".venv\Scripts\python.exe" (
    echo First run: creating virtual environment, please wait...
    python -m venv .venv || exit /b 1
)
echo Installing required packages, please wait...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt || exit /b 1
copy /y requirements.txt ".venv\requirements.installed" >nul
exit /b 0

:error
echo.
echo Setup failed. Check that:
echo   - Python 3.12 is installed and "Add python.exe to PATH" was ticked
echo   - this PC has internet access (the first run downloads about 100 MB)
echo   - this folder's path is at most about 80 characters long, e.g. C:\InfraChecker\
echo     (longer paths break the Qt package install unless Windows long path support is enabled)
echo Then run run.bat again; setup continues where it stopped.
pause
exit /b 1
