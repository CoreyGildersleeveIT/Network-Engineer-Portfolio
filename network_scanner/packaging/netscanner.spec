# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for NetScanner Pro.
Build with: pyinstaller packaging/netscanner.spec
"""

import sys
from pathlib import Path

block_cipher = None

root = Path(SPECPATH).parent
src = root

a = Analysis(
    [str(root / '__main__.py')],
    pathex=[str(root.parent)],
    binaries=[],
    datas=[],
    hiddenimports=[
        'PySide6.QtWidgets',
        'PySide6.QtCore',
        'PySide6.QtGui',
        'scapy.all',
        'pysnmp',
        'dns.resolver',
        'networkx',
        'jinja2',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'scipy', 'notebook', 'IPython'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='NetScannerPro',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='NetScannerPro',
)
