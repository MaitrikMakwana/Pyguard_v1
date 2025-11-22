#!/usr/bin/env python3
"""
Launcher script for PyGuard Desktop Application
Ensures the virtual environment is used for PyQt5 imports
"""

import sys
import os
import logging

def check_virtual_environment():
    """Check if we're running in the virtual environment"""
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        return True
    return False

def activate_virtual_environment():
    """Try to activate the virtual environment"""
    try:
        # Get the project root directory
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        venv_path = os.path.join(project_root, 'venv')
        
        if os.path.exists(venv_path):
            # Add virtual environment to Python path
            venv_site_packages = os.path.join(venv_path, 'Lib', 'site-packages')
            if os.path.exists(venv_site_packages):
                sys.path.insert(0, venv_site_packages)
                return True
        return False
    except Exception as e:
        print(f"Error activating virtual environment: {e}")
        return False

def main():
    """Main launcher function"""
    print("PyGuard Desktop Application Launcher")
    print("=" * 40)
    
    # Check if we're in virtual environment
    if not check_virtual_environment():
        print("[!] Not running in virtual environment")
        print("Attempting to activate virtual environment...")
        
        if activate_virtual_environment():
            print("[OK] Virtual environment activated")
        else:
            print("[X] Failed to activate virtual environment")
            print("\nPlease run this script from the virtual environment:")
            print("1. Open PowerShell in the project directory")
            print("2. Run: .\\venv\\Scripts\\Activate.ps1")
            print("3. Then run: python desktop_app\\run_desktop_app.py")
            input("\nPress Enter to exit...")
            return 1
    
    # Add the project root to Python path
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, project_root)
    
    try:
        # Try to import PyQt5 first to verify it's available
        import PyQt5
        print("[OK] PyQt5 available")
        
        # Now import and run the desktop app
        from desktop_app.desktop_app import main as desktop_main
        print("[OK] Desktop app imported successfully")
        print("[>] Starting PyGuard Desktop Application...")
        
        # Setup basic logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('pyguard_desktop.log')
            ]
        )
        
        # Create logger
        logger = logging.getLogger('pyguard')
        
        # Run the desktop application
        return desktop_main()
        
    except ImportError as e:
        print(f"[X] Import error: {e}")
        print("\nThis usually means PyQt5 is not available.")
        print("Please ensure you're running from the virtual environment:")
        print("1. Open PowerShell in the project directory")
        print("2. Run: .\\venv\\Scripts\\Activate.ps1")
        print("3. Then run: python desktop_app\\run_desktop_app.py")
        input("\nPress Enter to exit...")
        return 1
        
    except Exception as e:
        print(f"[X] Unexpected error: {e}")
        print("\nPlease check the error details above.")
        input("\nPress Enter to exit...")
        return 1

if __name__ == "__main__":
    sys.exit(main())