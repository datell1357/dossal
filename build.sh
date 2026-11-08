#!/bin/bash
# dossal build script: creates dossal.exe (Windows) or dossal (macOS/Linux)
# Usage: ./build.sh
# Requirements: pip install pyinstaller h2

set -e

echo "=== dossal v4.0 Build ==="
echo ""

# Install dependencies
echo "[1/3] Installing dependencies..."
pip install pyinstaller h2 2>/dev/null || pip3 install pyinstaller h2

# Build
echo "[2/3] Building EXE..."
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    # Windows
    pyinstaller --onefile --windowed \
        --name dossal \
        --hidden-import=h2 \
        --hidden-import=h2.connection \
        --hidden-import=h2.config \
        --hidden-import=h2.events \
        --add-data "dossal_gui.py;." \
        dossal_gui.py
    echo "Built: dist/dossal.exe"
else
    # macOS/Linux
    pyinstaller --onefile --windowed \
        --name dossal \
        --hidden-import=h2 \
        --hidden-import=h2.connection \
        --hidden-import=h2.config \
        --hidden-import=h2.events \
        --add-data "dossal_gui.py:." \
        dossal_gui.py
    echo "Built: dist/dossal"
fi

echo "[3/3] Done!"
echo ""
echo "Run: ./dist/dossal"
echo "Or copy to desktop and double-click"
echo ""
echo "For CLI only (no GUI):"
echo "  pyinstaller --onefile --name dossal-cli dossal.py"
