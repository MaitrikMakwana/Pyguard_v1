@echo off
echo PyGuard Virtual Environment Launcher
echo ========================================

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Run the launcher
echo Starting PyGuard...
python run_in_venv.py

REM Keep console open
pause
