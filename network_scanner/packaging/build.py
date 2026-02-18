#!/usr/bin/env python3
"""
Build script for NetScanner Pro.
Creates a standalone executable using PyInstaller.

Usage:
    python -m network_scanner.packaging.build
"""

import subprocess
import sys
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent.parent
    spec_file = root / "packaging" / "netscanner.spec"

    if not spec_file.exists():
        print(f"Spec file not found: {spec_file}")
        sys.exit(1)

    print("Building NetScanner Pro...")
    print(f"Spec file: {spec_file}")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "--distpath", str(root.parent / "dist"),
        "--workpath", str(root.parent / "build"),
        str(spec_file),
    ]

    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=str(root.parent))

    if result.returncode == 0:
        print("\nBuild successful!")
        print(f"Output: {root.parent / 'dist' / 'NetScannerPro'}")
    else:
        print("\nBuild failed!")
        sys.exit(result.returncode)


if __name__ == "__main__":
    main()
