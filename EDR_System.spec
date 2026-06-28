# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path


project = Path(SPECPATH).resolve()
datas = [
    (str(project / "threat_intel"), "threat_intel"),
    (str(project / "config"), "config"),
    (str(project / "rules"), "rules"),
]

a = Analysis(
    ["run_dashboard.py"],
    pathex=[str(project)],
    binaries=[],
    datas=datas,
    hiddenimports=["tkinter", "sqlite3", "multiprocessing"],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="EDR_System",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
)
