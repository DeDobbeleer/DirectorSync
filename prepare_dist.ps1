# Script pour preparer le dossier dist/ avec les fichiers necessaires
# Usage: powershell -ExecutionPolicy Bypass -File prepare_dist.ps1

$ErrorActionPreference = "Stop"

Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "Preparing dist/ folder for testing" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host ""

# Verifier que dist existe
if (-not (Test-Path "dist")) {
    Write-Host "ERROR: dist/ folder not found. Run build first!" -ForegroundColor Red
    exit 1
}

# Verifier que l'EXE existe
if (-not (Test-Path "dist\LPImporter.exe")) {
    Write-Host "ERROR: LPImporter.exe not found in dist/. Run build first!" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] LPImporter.exe found" -ForegroundColor Green

# 1. Copier .env
Write-Host ""
Write-Host "Copying .env..." -ForegroundColor Yellow
if (Test-Path ".env") {
    Copy-Item ".env" "dist\.env" -Force
    Write-Host "  [OK] .env copied" -ForegroundColor Green
} else {
    Write-Host "  [WARN] .env not found in project root" -ForegroundColor Yellow
}

# 2. Copier tenants.yml
Write-Host ""
Write-Host "Copying tenants.yml..." -ForegroundColor Yellow
if (Test-Path "tenants.yml") {
    Copy-Item "tenants.yml" "dist\tenants.yml" -Force
    Write-Host "  [OK] tenants.yml copied" -ForegroundColor Green
} else {
    Write-Host "  [WARN] tenants.yml not found in project root" -ForegroundColor Yellow
}

# 3. Creer resources/ et copier profiles.yml
Write-Host ""
Write-Host "Setting up resources/ folder..." -ForegroundColor Yellow
if (-not (Test-Path "dist\resources")) {
    New-Item -ItemType Directory -Path "dist\resources" -Force | Out-Null
    Write-Host "  [OK] resources/ folder created" -ForegroundColor Green
}

if (Test-Path "lp_tenant_importer_v2\resources\profiles.yml") {
    Copy-Item "lp_tenant_importer_v2\resources\profiles.yml" "dist\resources\profiles.yml" -Force
    Write-Host "  [OK] profiles.yml copied" -ForegroundColor Green
} else {
    Write-Host "  [WARN] profiles.yml not found" -ForegroundColor Yellow
}

# 4. Copier un fichier Excel d'exemple
Write-Host ""
Write-Host "Copying sample Excel file..." -ForegroundColor Yellow
$sampleXlsx = "lp_tenant_importer_v2\samples\core_config.xlsx"
if (Test-Path $sampleXlsx) {
    Copy-Item $sampleXlsx "dist\core_config.xlsx" -Force
    Write-Host "  [OK] core_config.xlsx copied" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Sample Excel not found" -ForegroundColor Yellow
}

# Resume
Write-Host ""
Write-Host "===========================================" -ForegroundColor Green
Write-Host "dist/ folder is ready!" -ForegroundColor Green
Write-Host "===========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Files in dist/:" -ForegroundColor Cyan
Get-ChildItem "dist\*" | ForEach-Object {
    $size = if ($_.PSIsContainer) { "<dir>" } else { "{0:N0} KB" -f ($_.Length / 1KB) }
    Write-Host "  - $($_.Name) $size" -ForegroundColor White
}

if (Test-Path "dist\resources") {
    Write-Host ""
    Write-Host "Files in dist/resources/:" -ForegroundColor Cyan
    Get-ChildItem "dist\resources\*" | ForEach-Object {
        $size = "{0:N0} KB" -f ($_.Length / 1KB)
        Write-Host "  - $($_.Name) $size" -ForegroundColor White
    }
}

Write-Host ""
Write-Host "Test commands:" -ForegroundColor Cyan
Write-Host "  cd dist" -ForegroundColor White
Write-Host "  .\LPImporter.exe --help" -ForegroundColor White
Write-Host "  .\LPImporter.exe --tenant core --xlsx core_config.xlsx repos --dry-run" -ForegroundColor White
Write-Host ""
