#!/usr/bin/env python3
"""
Test script to verify the stop button functionality in PyGuard desktop app
"""

import sys
import time
import logging
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QTimer

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_stop_functionality():
    """Test the stop button functionality"""
    try:
        # Import the desktop app
        from desktop_app.desktop_app import PyGuardDesktopApp
        
        app = QApplication(sys.argv)
        window = PyGuardDesktopApp()
        window.show()
        
        # Create a timer to automatically test stop functionality
        def auto_test():
            logger.info("Starting auto test...")
            
            # Start capture
            logger.info("Starting capture...")
            window.start_capture()
            
            # Wait 5 seconds
            QTimer.singleShot(5000, lambda: test_stop())
        
        def test_stop():
            logger.info("Testing stop functionality...")
            window.stop_capture()
            
            # Check if thread stopped
            QTimer.singleShot(2000, lambda: check_result())
        
        def check_result():
            if window.capture_thread and window.capture_thread.isRunning():
                logger.error("❌ FAIL: Thread is still running after stop")
            else:
                logger.info("✅ PASS: Thread stopped successfully")
            
            # Close the application
            QTimer.singleShot(1000, lambda: app.quit())
        
        # Start the auto test after 2 seconds
        QTimer.singleShot(2000, auto_test)
        
        return app.exec_()
        
    except Exception as e:
        logger.error(f"Error in test: {e}")
        return 1

if __name__ == "__main__":
    print("Testing PyGuard Stop Button Functionality")
    print("=" * 50)
    
    result = test_stop_functionality()
    
    if result == 0:
        print("✅ Test completed successfully")
    else:
        print("❌ Test failed")
    
    sys.exit(result)