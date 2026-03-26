#!/usr/bin/env python3
"""Entry point for PyInstaller - handles relative imports properly."""

import sys
import os

# Add the current directory to path so lp_tenant_importer_v2 can be imported
if getattr(sys, 'frozen', False):
    # Running as compiled executable
    bundle_dir = os.path.dirname(sys.executable)
else:
    # Running as script
    bundle_dir = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, bundle_dir)

# Now import and run the main module
from lp_tenant_importer_v2.main import main

if __name__ == "__main__":
    main()
