#!/bin/bash
# Aave Dashboard - Windows Distribution Build Script
# Creates standalone .exe for Windows distribution
# Note: This should be run on Windows with Python installed, or use Wine/WSL

echo "🚀 Building Aave Dashboard for Windows..."
echo ""

# Check Python version
PYTHON_VERSION=$(python --version 2>&1 | awk '{print $2}')
echo "✅ Using Python $PYTHON_VERSION"

# Check if PyInstaller is installed
if ! python -m pip list | grep -q pyinstaller; then
    echo "📦 Installing PyInstaller..."
    python -m pip install pyinstaller
fi

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf build dist *.spec

# Create the Windows executable
echo "📦 Creating Windows executable..."
python -m PyInstaller \
    --name="AaveDashboard" \
    --windowed \
    --onefile \
    --clean \
    --noconfirm \
    --add-data="logo_raw_b64.txt;." \
    --add-data="requirements.txt;." \
    --hidden-import=tkinter \
    --hidden-import=PIL._tkinter_finder \
    Combined_Dashboard_v2.py

# Check if build was successful
if [ -f "dist/AaveDashboard.exe" ]; then
    echo "✅ Build successful!"
    echo ""
    echo "📍 Location: dist/AaveDashboard.exe"
    echo ""
    echo "To distribute:"
    echo "  1. Copy the 'AaveDashboard.exe' file"
    echo "  2. Share with Windows users"
    echo "  3. Users double-click to run (no Python needed)"
    echo ""
    echo "⚠️  Note: Windows Defender may flag it. This is normal for PyInstaller apps."
else
    echo "❌ Build failed! Check errors above."
    exit 1
fi
