@echo off
echo PyGuard Desktop Application Launcher
echo ======================================

REM Change to project root directory
cd /d "%~dp0.."

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Run the desktop app
echo Starting PyGuard Desktop Application...
python desktop_app\run_desktop_app.py

REM Keep console open if there's an error
if errorlevel 1 (
    echo.
    echo An error occurred. Press any key to exit...
    pause >nul
)
