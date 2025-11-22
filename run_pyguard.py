#!/usr/bin/env python3
"""
PyGuard Desktop Application - Main Launcher
Clean launcher script for the desktop application
"""

import sys
import os

def main():
    """Main launcher function"""
    try:
        # Add desktop_app to path
        desktop_app_path = os.path.join(os.path.dirname(__file__), 'desktop_app')
        sys.path.insert(0, desktop_app_path)
        
        # Import and run the desktop app
        from desktop_app import main as desktop_main
        print("Starting PyGuard Desktop Application...")
        return desktop_main()
        
    except ImportError as e:
        print(f"Import error: {e}")
        print("Please install dependencies: pip install -r requirements.txt")
        return 1
    except Exception as e:
        print(f"Error starting application: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
