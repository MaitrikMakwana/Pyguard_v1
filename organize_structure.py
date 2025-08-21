#!/usr/bin/env python3
"""
File Structure Organizer for PyGuard Project
This script will organize all files into proper directories
"""

import os
import shutil
import sys

def create_directories():
    """Create the proper directory structure"""
    directories = [
        'tests',
        'scripts', 
        'debug',
        'tools',
        'docs',
        'examples',
        'config'
    ]
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"✓ Created directory: {directory}")
        else:
            print(f"✓ Directory exists: {directory}")

def move_files():
    """Move files to their proper locations"""
    
    # Test files
    test_files = [
        'test_stop_button.py',
        'test_unicode_csv.py', 
        'test_final_csv_fix.py',
        'test_packet_extraction.py',
        'test_csv_export.py',
        'test_csv_to_flows.py'
    ]
    
    for file in test_files:
        if os.path.exists(file):
            shutil.move(file, 'tests/')
            print(f"✓ Moved {file} to tests/")
    
    # Script files
    script_files = [
        'run_flow_analysis.py',
        'pcap_to_flows.py',
        'ml_flow_converter.py',
        'flow_analyzer.py',
        'demo_complete_workflow.py',
        'csv_to_flows.py',
        'debug_csv_issue.py',
        'capture_traffic.py',
        'complete_workflow_demo.py',
        'capture_to_csv.py',
        'complete_ml_pipeline.py',
        'enhanced_capture_all_formats.py',
        'enhanced_packet_extractor.py'
    ]
    
    for file in script_files:
        if os.path.exists(file):
            shutil.move(file, 'scripts/')
            print(f"✓ Moved {file} to scripts/")
    
    # Debug and utility files
    debug_files = [
        'debug_desktop_app.py',
        'minimal_test.py',
        'simple_launcher.py',
        'test_imports.py'
    ]
    
    for file in debug_files:
        if os.path.exists(file):
            shutil.move(file, 'debug/')
            print(f"✓ Moved {file} to debug/")
    
    # Documentation files
    doc_files = [
        'CSV_EXPORT_FIX_SUMMARY.md',
        'FLOW_ANALYSIS_README.md',
        'INDIVIDUAL_COLUMNS_FIX.md',
        'README_ML_WORKFLOW.md',
        'STOP_BUTTON_FIX.md',
        'USAGE.md'
    ]
    
    for file in doc_files:
        if os.path.exists(file):
            shutil.move(file, 'docs/')
            print(f"✓ Moved {file} to docs/")
    
    # Configuration files
    config_files = [
        'config.yaml'
    ]
    
    for file in config_files:
        if os.path.exists(file):
            shutil.move(file, 'config/')
            print(f"✓ Moved {file} to config/")
    
    # Example files
    example_files = [
        'test4949.pcap'
    ]
    
    for file in example_files:
        if os.path.exists(file):
            shutil.move(file, 'examples/')
            print(f"✓ Moved {file} to examples/")

def create_main_launcher():
    """Create a clean main launcher script"""
    launcher_content = '''#!/usr/bin/env python3
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
'''
    
    with open('run_pyguard.py', 'w') as f:
        f.write(launcher_content)
    print("✓ Created clean main launcher: run_pyguard.py")

def create_requirements_checker():
    """Create a requirements checker script"""
    checker_content = '''#!/usr/bin/env python3
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
        print(f"\\nMissing packages: {', '.join(missing_packages)}")
        print("Install with: pip install -r requirements.txt")
        return 1
    else:
        print("\\n✓ All required packages are installed!")
        return 0

if __name__ == "__main__":
    sys.exit(main())
'''
    
    with open('tools/check_requirements.py', 'w') as f:
        f.write(checker_content)
    print("✓ Created requirements checker: tools/check_requirements.py")

def main():
    """Main organization function"""
    print("=== PyGuard File Structure Organizer ===")
    
    print("\\n1. Creating directories...")
    create_directories()
    
    print("\\n2. Moving files to proper locations...")
    move_files()
    
    print("\\n3. Creating clean launcher...")
    create_main_launcher()
    
    print("\\n4. Creating utility scripts...")
    create_requirements_checker()
    
    print("\\n=== File structure organization completed! ===")
    print("\\nNew structure:")
    print("├── desktop_app/          # Main desktop application")
    print("├── pyguard/              # Core PyGuard modules")
    print("├── tests/                # Test files")
    print("├── scripts/              # Utility scripts")
    print("├── debug/                # Debug and test scripts")
    print("├── tools/                # Development tools")
    print("├── docs/                 # Documentation")
    print("├── examples/             # Example files")
    print("├── config/               # Configuration files")
    print("├── run_pyguard.py        # Clean main launcher")
    print("└── requirements.txt      # Dependencies")

if __name__ == "__main__":
    main()
