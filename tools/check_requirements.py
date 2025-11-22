#!/usr/bin/env python3
"""
Requirements Checker for PyGuard
Checks if all required packages are installed
"""

import sys
import subprocess

def check_package(package_name):
    """Check if a package is installed"""
    try:
        __import__(package_name)
        return True
    except ImportError:
        return False

def main():
    """Check all required packages"""
    required_packages = [
        'PyQt5',
        'scapy', 
        'psutil',
        'pandas',
        'yaml',
        'psycopg2',
        'pyarrow'
    ]
    
    print("=== PyGuard Requirements Checker ===")
    missing_packages = []
    
    for package in required_packages:
        if check_package(package):
            print(f"✓ {package} - Installed")
        else:
            print(f"✗ {package} - Missing")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\nMissing packages: {', '.join(missing_packages)}")
        print("Install with: pip install -r requirements.txt")
        return 1
    else:
        print("\n✓ All required packages are installed!")
        return 0

if __name__ == "__main__":
    sys.exit(main())
