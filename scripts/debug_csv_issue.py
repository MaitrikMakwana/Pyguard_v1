#!/usr/bin/env python3
"""
Debug script to help identify CSV export issues in PyGuard Desktop App
"""

import os
import sys
import csv
import tempfile
from pathlib import Path

def check_file_permissions():
    """Check if we can create files in various locations"""
    print("🔍 Checking file permissions...")
    
    locations_to_test = [
        Path.cwd(),  # Current directory
        Path.home() / "Desktop",  # Desktop
        Path.home() / "Documents",  # Documents
        Path(tempfile.gettempdir()),  # Temp directory
    ]
    
    for location in locations_to_test:
        try:
            if location.exists():
                test_file = location / "pyguard_test.csv"
                
                # Try to create a test file
                with open(test_file, 'w') as f:
                    f.write("test,data\n1,2\n")
                
                # Try to read it back
                with open(test_file, 'r') as f:
                    content = f.read()
                
                # Clean up
                test_file.unlink()
                
                print(f"   ✅ {location}: Read/Write OK")
            else:
                print(f"   ⚠️  {location}: Directory doesn't exist")
                
        except Exception as e:
            print(f"   ❌ {location}: Error - {e}")

def check_csv_module():
    """Check if CSV module is working correctly"""
    print("\n🔍 Checking CSV module functionality...")
    
    try:
        import csv
        import io
        
        # Test CSV writing to string buffer
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=['name', 'value'])
        writer.writeheader()
        writer.writerow({'name': 'test', 'value': 123})
        
        result = output.getvalue()
        print(f"   ✅ CSV module working: {len(result)} characters written")
        print(f"   📝 Sample output: {repr(result[:50])}")
        
    except Exception as e:
        print(f"   ❌ CSV module error: {e}")

def check_qt_file_dialog():
    """Check if Qt file dialog components are available"""
    print("\n🔍 Checking Qt file dialog components...")
    
    try:
        from PyQt5.QtWidgets import QApplication, QFileDialog
        print("   ✅ PyQt5 QFileDialog imported successfully")
        
        # Check if we can create a QApplication (needed for dialogs)
        app = QApplication.instance()
        if app is None:
            print("   ⚠️  No QApplication instance found (normal if not in GUI mode)")
        else:
            print("   ✅ QApplication instance exists")
            
    except ImportError as e:
        print(f"   ❌ PyQt5 import error: {e}")
        
        # Try PyQt6 as fallback
        try:
            from PyQt6.QtWidgets import QApplication, QFileDialog
            print("   ✅ PyQt6 QFileDialog imported successfully (fallback)")
        except ImportError as e2:
            print(f"   ❌ PyQt6 import error: {e2}")

def simulate_desktop_app_save():
    """Simulate the desktop app's CSV save process"""
    print("\n🔍 Simulating desktop app CSV save process...")
    
    # Simulate captured packets (like in desktop app)
    captured_packets = [
        {
            'frame_number': 1,
            'timestamp': '2025-01-04 12:00:00.123456',
            'src_ip': '192.168.1.100',
            'src_port': 12345,
            'dst_ip': '8.8.8.8',
            'dst_port': 53,
            'protocol': 'UDP',
            'size': 64,
            'summary': 'DNS Query for google.com',
            'extra_field': {'complex': 'data'}  # Test complex data handling
        }
    ]
    
    # Use the same fields as desktop app
    fields = ['frame_number', 'timestamp', 'src_ip', 'src_port', 
              'dst_ip', 'dst_port', 'protocol', 'size', 'summary']
    
    try:
        # Create test file
        test_file = Path("debug_test_export.csv")
        
        with open(test_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
            writer.writeheader()
            
            for i, packet in enumerate(captured_packets):
                # Create a clean row with only simple values (same logic as desktop app)
                row = {}
                for field in fields:
                    if field in packet:
                        # Convert complex objects to strings
                        if isinstance(packet[field], (dict, list)):
                            row[field] = str(packet[field])
                        else:
                            row[field] = packet[field]
                    elif field == 'frame_number' and 'frame_number' not in packet:
                        # Add frame number if not present
                        row[field] = i + 1
                
                writer.writerow(row)
        
        # Verify file was created
        if test_file.exists():
            file_size = test_file.stat().st_size
            print(f"   ✅ Desktop app simulation successful")
            print(f"   📁 File: {test_file.absolute()}")
            print(f"   📊 Size: {file_size} bytes")
            
            # Show content
            with open(test_file, 'r') as f:
                content = f.read()
                print(f"   📝 Content preview:\n{content}")
            
            # Clean up
            test_file.unlink()
            
        return True
        
    except Exception as e:
        print(f"   ❌ Desktop app simulation failed: {e}")
        return False

def check_common_issues():
    """Check for common issues that prevent CSV export"""
    print("\n🔍 Checking for common CSV export issues...")
    
    issues_found = []
    
    # Check disk space
    try:
        import shutil
        free_space = shutil.disk_usage('.').free
        free_mb = free_space / (1024 * 1024)
        
        if free_mb < 100:  # Less than 100MB
            issues_found.append(f"Low disk space: {free_mb:.1f} MB free")
        else:
            print(f"   ✅ Disk space OK: {free_mb:.1f} MB free")
    except Exception as e:
        issues_found.append(f"Cannot check disk space: {e}")
    
    # Check if running as administrator (Windows)
    if sys.platform == 'win32':
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if is_admin:
                print("   ℹ️  Running as administrator")
            else:
                print("   ℹ️  Running as regular user")
        except:
            print("   ⚠️  Cannot determine admin status")
    
    # Check current working directory
    cwd = Path.cwd()
    print(f"   📁 Current directory: {cwd}")
    
    if issues_found:
        print("\n⚠️  Potential issues found:")
        for issue in issues_found:
            print(f"   - {issue}")
    else:
        print("   ✅ No common issues detected")

def main():
    """Main diagnostic function"""
    print("🔧 PyGuard CSV Export Diagnostic Tool")
    print("=" * 60)
    
    check_file_permissions()
    check_csv_module()
    check_qt_file_dialog()
    simulate_desktop_app_save()
    check_common_issues()
    
    print("\n" + "=" * 60)
    print("🎯 TROUBLESHOOTING STEPS:")
    print("1. Make sure you have captured some packets first")
    print("2. Click the '💾 Save' button in the toolbar")
    print("3. In the file dialog, select 'CSV files (*.csv)' from the dropdown")
    print("4. Choose a location where you have write permissions")
    print("5. Enter a filename and click Save")
    print("\n💡 If it still doesn't work:")
    print("- Try saving to Desktop or Documents folder")
    print("- Check if antivirus is blocking file creation")
    print("- Run the desktop app as administrator")
    print("- Check the application logs for error messages")

if __name__ == "__main__":
    main()