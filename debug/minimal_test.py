#!/usr/bin/env python3
"""
Minimal PyQt5 test to see if the basic GUI works
"""

import sys

try:
    print("Testing PyQt5 import...")
    from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel
    from PyQt5.QtCore import Qt
    print("✓ PyQt5 imported successfully")
    
    print("Creating QApplication...")
    app = QApplication(sys.argv)
    print("✓ QApplication created")
    
    print("Creating main window...")
    window = QMainWindow()
    window.setWindowTitle("PyGuard Test Window")
    window.setGeometry(100, 100, 400, 300)
    
    # Add a label
    label = QLabel("PyGuard Desktop App Test - If you see this, PyQt5 is working!", window)
    label.setAlignment(Qt.AlignCenter)
    label.setGeometry(50, 100, 300, 100)
    
    print("Showing window...")
    window.show()
    print("✓ Window displayed")
    
    print("Starting event loop...")
    print("   Close the window to continue...")
    result = app.exec_()
    print(f"✓ Application exited with code: {result}")
    
except ImportError as e:
    print(f"✗ Import error: {e}")
    print("Install PyQt5 with: pip install PyQt5")
    sys.exit(1)
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("✓ Minimal test completed successfully!")
