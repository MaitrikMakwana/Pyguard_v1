#!/usr/bin/env python3
"""
Debug launcher for PyGuard Desktop Application
This will show exactly what's happening when the app starts
"""

import sys
import os
import traceback

print("=== PyGuard Desktop App Debug Launcher ===")
print(f"Python version: {sys.version}")
print(f"Current directory: {os.getcwd()}")
print(f"Python path: {sys.path[:3]}...")  # Show first 3 paths

try:
    print("\n1. Testing basic imports...")
    import sys
    print("✓ sys imported")
    
    print("\n2. Testing PyQt5 import...")
    try:
        from PyQt5.QtWidgets import QApplication
        print("✓ PyQt5.QtWidgets imported successfully")
    except ImportError as e:
        print(f"✗ PyQt5 import failed: {e}")
        print("   Install with: pip install PyQt5")
        sys.exit(1)
    
    print("\n3. Testing Scapy import...")
    try:
        import scapy
        print("✓ Scapy imported successfully")
    except ImportError as e:
        print(f"✗ Scapy import failed: {e}")
        print("   Install with: pip install scapy")
        sys.exit(1)
    
    print("\n4. Testing other dependencies...")
    try:
        import psutil
        print("✓ psutil imported")
    except ImportError as e:
        print(f"✗ psutil import failed: {e}")
    
    try:
        import pandas
        print("✓ pandas imported")
    except ImportError as e:
        print(f"✗ pandas import failed: {e}")
    
    print("\n5. Importing desktop app...")
    try:
        # Add desktop_app to path
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'desktop_app'))
        from desktop_app import main
        print("✓ desktop_app imported successfully")
    except ImportError as e:
        print(f"✗ desktop_app import failed: {e}")
        print(f"   Full error: {traceback.format_exc()}")
        sys.exit(1)
    
    print("\n6. Starting desktop application...")
    print("   If the app exits immediately, check the console for errors")
    
    # Start the application
    result = main()
    print(f"   Application exited with code: {result}")
    
except Exception as e:
    print(f"\n❌ CRITICAL ERROR: {e}")
    print(f"Full traceback:\n{traceback.format_exc()}")
    sys.exit(1)

print("\n=== Debug launcher completed ===")
