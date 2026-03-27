# Building LPImporter Windows Executable

## Method 1: PowerShell Script (Recommended)

On Windows with Python installed:

```powershell
# Run PowerShell script
powershell -ExecutionPolicy Bypass -File build_windows.ps1
```

This will:
1. Check Python installation
2. Install/upgrade PyInstaller
3. Install requirements
4. Build the executable
5. Create `LPImporter.zip` for distribution

## Method 2: Batch Script

```cmd
# Run batch script
build_windows.bat
```

## Method 3: Manual Build

```bash
# Install PyInstaller
pip install pyinstaller

# Install requirements
pip install -r lp_tenant_importer_v2/requirements.txt

# Clean previous builds
rmdir /s /q build dist

# Build
pyinstaller build.spec --clean
```

## Output

After successful build:
- **Executable**: `dist/LPImporter/LPImporter.exe`
- **Distribution**: `LPImporter.zip`

## Runtime Requirements

Copy these files alongside the executable:
- `tenants.yml` - Tenant configuration
- `.env` (optional) - Environment variables

## Usage

```cmd
# Show help
LPImporter.exe --help

# Import alerts
LPImporter.exe alerts --tenant "MyTenant" --xlsx "config.xlsx"

# Dry run
LPImporter.exe alerts --tenant "MyTenant" --xlsx "config.xlsx" --dry-run
```

## Troubleshooting

### ImportError: cannot import name 'ValidationError'
**Fixed**: This was caused by `ValidationError` not being exported from `base.py`. 
Ensure you have the latest code where `base.py` imports `ValidationError` from `validators`.

### Other missing imports
If you get import errors like `ImportError: cannot import name 'X' from 'Y'`, add the missing module to `hiddenimports` in `build.spec` and rebuild.

### Clean rebuild
Always clean before rebuilding to avoid stale cache:
```bash
rmdir /s /q build dist
pyinstaller build.spec --clean
```

### Large file size
The executable includes Python and all dependencies (~15-30MB). This is normal.

### Anti-virus false positive
Some anti-virus tools may flag PyInstaller executables. Add an exclusion or use code signing.
