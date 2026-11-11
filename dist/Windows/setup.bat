@echo off
echo ========================================
echo  dossal v4.5.1 - First Run Setup
echo ========================================
echo.
echo Installing Python dependencies...
echo.

python get-pip.py
python -m pip install h2 psutil --quiet

echo.
echo Setup complete!
echo Running dossal GUI...
echo.
python dossal_gui.py
pause
