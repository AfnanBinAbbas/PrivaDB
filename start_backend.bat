@echo off
echo Starting Data Whisperer Backend...
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Check if requirements are installed
python -c "import fastapi" >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies...
    pip install -r requirements.txt
    echo.
    echo Installing Playwright browsers...
    playwright install chromium
    echo.
)

REM Start the backend server
echo Starting FastAPI server on http://localhost:8000
echo Press Ctrl+C to stop
echo.
python backend.py

pause
