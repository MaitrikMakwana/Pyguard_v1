# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['D:\\PyGuard-main\\desktop_app\\desktop_app.py'],
    pathex=[],
    binaries=[],
    datas=[('D:\\PyGuard-main\\config', 'config'), ('D:\\PyGuard-main\\docs', 'docs'), ('D:\\PyGuard-main\\Final_IDS', 'Final_IDS')],
    hiddenimports=['PyQt5', 'scapy', 'pandas', 'numpy', 'sqlalchemy', 'psycopg2', 'desktop_app.ids_service_manager', 'ids_service_manager', 'Final_IDS.app.main'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='PyGuard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
