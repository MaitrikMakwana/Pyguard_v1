#!/usr/bin/env python3
"""
PyGuard EXE Builder Script
Builds a standalone executable using PyInstaller
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

# Force UTF-8 encoding on Windows
import io
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

def build_pyguard_exe():
    """Build PyGuard as a standalone exe using PyInstaller"""
    
    # Get project root
    project_root = Path(__file__).parent.resolve()
    desktop_app_dir = project_root / "desktop_app"
    main_script = desktop_app_dir / "desktop_app.py"
    
    # Output directories
    dist_dir = project_root / "dist"
    
    print("=" * 60)
    print("PyGuard EXE Builder")
    print("=" * 60)
    print(f"Project root: {project_root}")
    print(f"Main script: {main_script}")
    print(f"Dist dir: {dist_dir}")
    print()
    
    # Verify main script exists
    if not main_script.exists():
        print(f"ERROR: Main script not found at {main_script}")
        return False
    
    # Clean previous builds (optional - comment out to keep old builds)
    print("Cleaning previous builds...")
    for old_dir in [dist_dir]:
        if old_dir.exists():
            print(f"  Removing {old_dir}")
            shutil.rmtree(old_dir, ignore_errors=True)
    
    # PyInstaller command - use correct syntax for newer versions
    # Add error handling for netifaces import
    try:
        import netifaces
        hidden_imports = [
            'PyQt5', 'scapy', 'pandas', 'numpy', 'sqlalchemy', 'psycopg2', 'netifaces',
            'desktop_app.ids_service_manager', 'ids_service_manager', 'Final_IDS.app.main'
        ]
    except ImportError:
        print("Warning: netifaces not found, building without network interface support")
        hidden_imports = [
            'PyQt5', 'scapy', 'pandas', 'numpy', 'sqlalchemy', 'psycopg2',
            'desktop_app.ids_service_manager', 'ids_service_manager', 'Final_IDS.app.main'
        ]
    
    pyinstaller_cmd = [
        sys.executable, '-m', 'PyInstaller',
        '--name', 'PyGuard',
        '-F',  # Create a single file executable
        '-w',  # Windowed mode (no console)
        '--add-data', f'{project_root / "config"}{os.pathsep}config',
        '--add-data', f'{project_root / "docs"}{os.pathsep}docs',
        '--add-data', f'{project_root / "Final_IDS"}{os.pathsep}Final_IDS',
    ]
    
    # Add hidden imports
    for imp in hidden_imports:
        pyinstaller_cmd.extend(['--hidden-import', imp])
    
    # Add final arguments
    pyinstaller_cmd.extend([
        '--distpath', str(dist_dir),
        str(main_script)
    ])
    
    # Add icon if it exists
    icon_path = desktop_app_dir / "pyguard_icon.ico"
    if icon_path.exists():
        pyinstaller_cmd.extend(["-i", str(icon_path)])
    
    print("Building executable with PyInstaller...")
    print(f"Command: {' '.join(pyinstaller_cmd)}")
    print()
    
    try:
        result = subprocess.run(pyinstaller_cmd, cwd=project_root, check=True)
        
        print()
        print("=" * 60)
        print("[OK] BUILD SUCCESS!")
        print("=" * 60)
        exe_path = dist_dir / "PyGuard.exe"
        print(f"Executable created: {exe_path}")
        print()
        print("Next steps:")
        print("1. Run the exe: dist\\PyGuard.exe")
        print("2. Or create a shortcut for easy access")
        print("3. You can distribute the exe to other machines")
        print()
        
        return True
        
    except subprocess.CalledProcessError as e:
        print()
        print("=" * 60)
        print("[X] BUILD FAILED")
        print("=" * 60)
        print(f"Error: {e}")
        print()
        print("Troubleshooting:")
        print("1. Ensure all dependencies are installed: pip install -r requirements.txt")
        print("2. Check that desktop_app.py exists and is valid Python")
        print("3. Review the error messages above")
        print()
        return False

if __name__ == "__main__":
    success = build_pyguard_exe()
    sys.exit(0 if success else 1)
