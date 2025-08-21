#!/usr/bin/env python3
"""
Test script to check if all imports work correctly
"""

import sys
import os

print("Testing imports...")

try:
    print("✓ Python version:", sys.version)
except Exception as e:
    print("✗ Python version error:", e)

try:
    import PyQt5
    print("✓ PyQt5 imported successfully")
except ImportError as e:
    print("✗ PyQt5 import failed:", e)

try:
    import scapy
    print("✓ Scapy imported successfully")
except ImportError as e:
    print("✗ Scapy import failed:", e)

try:
    import psutil
    print("✓ psutil imported successfully")
except ImportError as e:
    print("✗ psutil import failed:", e)

try:
    import pandas
    print("✓ pandas imported successfully")
except ImportError as e:
    print("✗ pandas import failed:", e)

try:
    import yaml
    print("✓ PyYAML imported successfully")
except ImportError as e:
    print("✗ PyYAML import failed:", e)

print("\nImport test completed!")
