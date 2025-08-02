#!/usr/bin/env python3
"""
Launcher script for PyGuard Desktop Application
"""

import sys
import logging
from desktop_app import main

if __name__ == "__main__":
    # Setup basic logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('pyguard_desktop.log')
        ]
    )
    
    # Create logger
    logger = logging.getLogger('pyguard')
    
    # Run the desktop application
    sys.exit(main())