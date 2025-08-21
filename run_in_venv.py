#!/usr/bin/env python3
"""
PyGuard Launcher for Virtual Environment
This script runs PyGuard with available modules, avoiding problematic ones.
"""

import sys
import os

def main():
    print("PyGuard Virtual Environment Launcher")
    print("=" * 40)
    
    # Add the current directory to Python path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    try:
        # Import and run the main application
        from pyguard.main import main as pyguard_main
        print("✓ Starting PyGuard...")
        pyguard_main()
    except ImportError as e:
        print(f"✗ Failed to import main module: {e}")
        print("\nTrying alternative launcher...")
        
        try:
            # Try the desktop app instead
            from desktop_app.desktop_app import main as desktop_main
            print("✓ Starting Desktop App...")
            desktop_main()
        except ImportError as e2:
            print(f"✗ Desktop app also failed: {e2}")
            print("\nAvailable options:")
            print("1. Install Microsoft Visual C++ Build Tools for full functionality")
            print("2. Use the working modules (storage, system monitoring)")
            print("3. Run individual scripts that don't require packet capture")
            
            # Try to run a simple demo
            try:
                print("\nTrying to run a simple demo...")
                from scripts.demo_complete_workflow import main as demo_main
                demo_main()
            except ImportError as e3:
                print(f"✗ Demo also failed: {e3}")
                print("\nThe virtual environment is set up but some modules need compilation.")
                print("You can still use the basic functionality.")

if __name__ == "__main__":
    main()
