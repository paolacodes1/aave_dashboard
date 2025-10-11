# Windows Build Instructions for Aave Dashboard

## 📦 Package Contents

This folder contains everything needed to build the Windows executable:

- `Combined_Dashboard_v2.py` - Main GUI application
- `aave_api.py` - API client for Aave data
- `logo_raw_b64.txt` - Application logo (base64 encoded)
- `requirements.txt` - Python dependencies
- `build_windows.sh` - Build script (for Git Bash/WSL)
- `BUILD_INSTRUCTIONS.md` - This file

## 🔧 Prerequisites

### Required Software:
1. **Python 3.8+** - Download from [python.org](https://www.python.org/downloads/)
   - ✅ During installation, check "Add Python to PATH"
2. **Git Bash** (optional) - For running the build script
   - Or use Command Prompt/PowerShell with manual commands

## 📋 Step-by-Step Build Process

### Option 1: Using the Build Script (Git Bash/WSL)

1. Open **Git Bash** or **WSL**
2. Navigate to this folder:
   ```bash
   cd /path/to/windows_build_package
   ```
3. Make the script executable:
   ```bash
   chmod +x build_windows.sh
   ```
4. Run the build script:
   ```bash
   ./build_windows.sh
   ```

### Option 2: Manual Build (Command Prompt/PowerShell)

1. Open **Command Prompt** or **PowerShell** as Administrator
2. Navigate to this folder:
   ```cmd
   cd C:\path\to\windows_build_package
   ```
3. Install dependencies:
   ```cmd
   python -m pip install -r requirements.txt
   python -m pip install pyinstaller
   ```
4. Clean previous builds (if any):
   ```cmd
   rmdir /s /q build dist
   del /q *.spec
   ```
5. Build the executable:
   ```cmd
   python -m PyInstaller --name="AaveDashboard" --windowed --onefile --clean --noconfirm --add-data="logo_raw_b64.txt;." --add-data="requirements.txt;." --hidden-import=tkinter --hidden-import=PIL._tkinter_finder Combined_Dashboard_v2.py
   ```

## ✅ Verification

After the build completes successfully, you should have:

```
dist/
  └── AaveDashboard.exe    ← This is your distributable file!
```

### Test the executable:
1. Navigate to the `dist` folder
2. Double-click `AaveDashboard.exe`
3. The application should launch with a GUI window

## 📤 Distribution

Once built, you can share **only** the `AaveDashboard.exe` file:

1. Copy `dist/AaveDashboard.exe`
2. Share it with Windows users
3. Users simply double-click to run (no Python installation needed!)

## ⚠️ Common Issues

### Issue: "Python is not recognized as a command"
**Solution**: Reinstall Python and check "Add Python to PATH" during installation

### Issue: Windows Defender blocks the .exe
**Solution**: This is normal for PyInstaller applications
- Click "More info" → "Run anyway"
- Or add an exception in Windows Defender

### Issue: "tkinter module not found"
**Solution**: Reinstall Python with tcl/tk support:
```cmd
python -m pip install --upgrade tk
```

### Issue: Build fails with "No module named 'PIL'"
**Solution**: Install Pillow:
```cmd
python -m pip install Pillow
```

## 🔄 Rebuilding After Code Changes

If you make changes to the Python files:

1. Delete the old build:
   ```cmd
   rmdir /s /q build dist
   del /q *.spec
   ```
2. Run the build command again (step 5 from Option 2)

## 📝 Notes

- The build process takes 2-5 minutes depending on your system
- The final `.exe` file will be approximately 15-25 MB
- No additional files are needed - everything is bundled into the single `.exe`
- The executable includes all the latest fixes:
  - Fixed card layout widths
  - Health factor displays ∞ for no-debt positions
  - All network detection improvements

## 🆘 Support

If you encounter issues:
1. Check that Python 3.8+ is installed: `python --version`
2. Verify PyInstaller is installed: `python -m pip show pyinstaller`
3. Check the error messages in the build output
4. Ensure all files from this package are in the same folder

---

**Version**: 2.0 (Latest with UI fixes)
**Build Date**: October 10, 2025
**Built by**: Claude Code
