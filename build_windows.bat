@echo off
REM Build script for LPImporter Windows executable
REM Run this on Windows with Python installed

echo ===========================================
echo Building LPImporter Windows Executable
echo ===========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    exit /b 1
)

echo Python version:
python --version
echo.

REM Install/upgrade PyInstaller if needed
echo Installing PyInstaller...
pip install pyinstaller --upgrade
if errorlevel 1 (
    echo ERROR: Failed to install PyInstaller
    exit /b 1
)

REM Install requirements
echo Installing requirements...
pip install -r lp_tenant_importer_v2\requirements.txt --upgrade
if errorlevel 1 (
    echo ERROR: Failed to install requirements
    exit /b 1
)

REM Clean previous builds
echo Cleaning previous builds...
if exist "build" rmdir /s /q build
if exist "dist" rmdir /s /q dist

REM Build executable
echo Building executable...
pyinstaller build.spec --clean
if errorlevel 1 (
    echo ERROR: Build failed
    exit /b 1
)

echo.
echo ===========================================
echo Build completed successfully!
echo Output: dist\LPImporter\LPImporter.exe
echo ===========================================
echo.
echo Files to distribute:
echo   - dist\LPImporter\LPImporter.exe
echo   - dist\LPImporter\*.dll (if any)
echo   - dist\LPImporter\lp_tenant_importer_v2\resources\* (config files)
echo.
echo Optional: Copy tenants.yml and .env alongside the executable
echo for configuration at runtime.
pause
