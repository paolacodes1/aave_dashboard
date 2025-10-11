@echo off
REM Aave Dashboard - Windows Distribution Build Script
REM Creates standalone .exe for Windows distribution

echo ========================================
echo  Aave Dashboard - Windows Build Script
echo ========================================
echo.

REM Check Python version
python --version
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo.
echo [1/5] Installing dependencies...
python -m pip install -r requirements.txt
python -m pip install pyinstaller

echo.
echo [2/5] Cleaning previous builds...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist *.spec del /q *.spec

echo.
echo [3/5] Building Windows executable...
python -m PyInstaller ^
    --name="AaveDashboard" ^
    --windowed ^
    --onefile ^
    --clean ^
    --noconfirm ^
    --add-data="logo_raw_b64.txt;." ^
    --add-data="requirements.txt;." ^
    --hidden-import=tkinter ^
    --hidden-import=PIL._tkinter_finder ^
    Combined_Dashboard_v2.py

echo.
echo [4/5] Verifying build...
if exist "dist\AaveDashboard.exe" (
    echo.
    echo ========================================
    echo  BUILD SUCCESSFUL!
    echo ========================================
    echo.
    echo Location: dist\AaveDashboard.exe
    echo.
    echo To distribute:
    echo   1. Copy dist\AaveDashboard.exe
    echo   2. Share with Windows users
    echo   3. Users double-click to run
    echo.
    echo NOTE: Windows Defender may flag it as unknown.
    echo       This is normal for PyInstaller apps.
    echo       Click "More info" then "Run anyway"
    echo.
    pause
) else (
    echo.
    echo ========================================
    echo  BUILD FAILED!
    echo ========================================
    echo.
    echo Check the error messages above.
    echo.
    pause
    exit /b 1
)
