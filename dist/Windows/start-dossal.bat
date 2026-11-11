@echo off
echo ========================================
echo  dossal v4.5.1 - Windows Launcher
echo ========================================
echo.

# Check if Python is installed
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python not found!
    echo Please install Python 3.8+ from: https://www.python.org/downloads/
    echo Then run this file again.
    pause
    exit /b 1
)

# Check if required modules are installed
python -c "import h2" >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Installing h2 module...
    pip install h2
)

python -c "import psutil" >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Installing psutil module...
    pip install psutil
)

echo.
echo Starting dossal GUI...
echo.
python dossal_gui.py
pause
