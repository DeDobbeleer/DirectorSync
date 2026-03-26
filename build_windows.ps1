# Build script for LPImporter Windows executable
# Run with: powershell -ExecutionPolicy Bypass -File build_windows.ps1

$ErrorActionPreference = "Stop"

Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "Building LPImporter Windows Executable" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host ""

# Check Python
Write-Host "Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Python is not installed or not in PATH" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Install dependencies
Write-Host "Installing dependencies..." -ForegroundColor Yellow
pip install pyinstaller --upgrade -q
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to install PyInstaller" -ForegroundColor Red
    exit 1
}

pip install -r lp_tenant_importer_v2\requirements.txt --upgrade -q
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to install requirements" -ForegroundColor Red
    exit 1
}
Write-Host "Dependencies installed successfully" -ForegroundColor Green
Write-Host ""

# Clean previous builds
Write-Host "Cleaning previous builds..." -ForegroundColor Yellow
if (Test-Path "build") {
    Remove-Item -Path "build" -Recurse -Force
}
if (Test-Path "dist") {
    Remove-Item -Path "dist" -Recurse -Force
}
Write-Host "Cleaned" -ForegroundColor Green
Write-Host ""

# Build executable
Write-Host "Building executable..." -ForegroundColor Yellow
pyinstaller build.spec --clean
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Build failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "===========================================" -ForegroundColor Green
Write-Host "Build completed successfully!" -ForegroundColor Green
Write-Host "Output: dist\LPImporter\LPImporter.exe" -ForegroundColor Green
Write-Host "===========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Files to distribute:" -ForegroundColor Cyan
Write-Host "  - dist\LPImporter\LPImporter.exe" -ForegroundColor White
Write-Host "  - dist\LPImporter\*.dll (if any)" -ForegroundColor White
Write-Host "  - dist\LPImporter\lp_tenant_importer_v2\resources\*" -ForegroundColor White
Write-Host ""
Write-Host "Optional configuration files (copy alongside exe):" -ForegroundColor Cyan
Write-Host "  - tenants.yml" -ForegroundColor White
Write-Host "  - .env" -ForegroundColor White
Write-Host ""

# Create distribution zip
$zipFile = "LPImporter.zip"
if (Test-Path $zipFile) {
    Remove-Item $zipFile -Force
}
Compress-Archive -Path "dist\LPImporter" -DestinationPath $zipFile -Force
Write-Host "Created distribution archive: $zipFile" -ForegroundColor Green

Write-Host ""
Read-Host -Prompt "Press Enter to exit"
