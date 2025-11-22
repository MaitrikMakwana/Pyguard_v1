#!/usr/bin/env python3
"""
Simple launcher for PyGuard Desktop Application
"""

import sys
import os

# Add the desktop_app directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'desktop_app'))

try:
    # Import and run the desktop app
    from desktop_app import main
    print("Starting PyGuard Desktop Application...")
    sys.exit(main())
except ImportError as e:
    print(f"Import error: {e}")
    print("Please make sure all dependencies are installed:")
    print("pip install -r requirements.txt")
    sys.exit(1)
except Exception as e:
    print(f"Error starting application: {e}")
    sys.exit(1)
