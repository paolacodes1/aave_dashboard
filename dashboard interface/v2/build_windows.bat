@echo off
echo Building Windows executable for Aave Dashboard v2.0...
echo.

REM Create icons if they don't exist
if not exist logo.ico (
    echo Creating icon files...
    python create_icons.py
)

REM Build the executable
echo Building executable...
pyinstaller --clean build_windows.spec

REM Check if build was successful
if exist "dist\AaveDashboard.exe" (
    echo.
    echo ✓ Build successful!
    echo Executable created: dist\AaveDashboard.exe
    echo.
    echo You can now distribute the following files:
    echo - dist\AaveDashboard.exe
    echo.
    echo The executable includes all dependencies and the logo.
) else (
    echo.
    echo ✗ Build failed!
    echo Check the output above for errors.
)

pause