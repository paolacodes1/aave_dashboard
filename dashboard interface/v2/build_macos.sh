#!/bin/bash
# Aave Dashboard - macOS Distribution Build Script
# Creates standalone .app bundle for macOS distribution

echo "🚀 Building Aave Dashboard for macOS..."
echo ""

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "✅ Using Python $PYTHON_VERSION"

# Check if PyInstaller is installed
if ! python3 -m pip list | grep -q pyinstaller; then
    echo "📦 Installing PyInstaller..."
    python3 -m pip install pyinstaller
fi

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf build dist *.spec

# Create the macOS app bundle
echo "📦 Creating macOS application bundle..."
python3 -m PyInstaller \
    --name="AaveDashboard" \
    --windowed \
    --onedir \
    --clean \
    --noconfirm \
    --add-data="logo_raw_b64.txt:." \
    --add-data="requirements.txt:." \
    --hidden-import=tkinter \
    --hidden-import=PIL._tkinter_finder \
    Combined_Dashboard_v2.py

# Check if build was successful
if [ -d "dist/AaveDashboard.app" ]; then
    echo "✅ Build successful!"
    echo ""
    echo "📍 Location: dist/AaveDashboard.app"
    echo ""
    echo "To distribute:"
    echo "  1. Copy the entire 'AaveDashboard.app' folder"
    echo "  2. Share with Mac users"
    echo "  3. Users double-click to run (no Python needed)"
    echo ""
    echo "⚠️  Note: Users may need to allow the app in System Preferences > Security & Privacy"
else
    echo "❌ Build failed! Check errors above."
    exit 1
fi
