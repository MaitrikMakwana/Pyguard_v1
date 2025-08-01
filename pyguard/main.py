#!/usr/bin/env python3
"""
PyGuard - Main entry point for the application
"""

import sys
import argparse
import logging
from pathlib import Path

from pyguard.core.config import Config
from pyguard.core.capture_manager import CaptureManager
from pyguard.ui.app import start_gui

logger = logging.getLogger(__name__)

def setup_logging(config):
    """Configure logging based on configuration"""
    log_level = getattr(logging, config.log_level.upper())
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.FileHandler(config.log_file),
            logging.StreamHandler()
        ]
    )

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='PyGuard - Network Traffic Metadata Capture')
    parser.add_argument('-c', '--config', type=str, default='config.yaml',
                        help='Path to configuration file')
    parser.add_argument('--no-gui', action='store_true',
                        help='Run in headless mode without GUI')
    parser.add_argument('-i', '--interface', type=str,
                        help='Network interface to capture from')
    parser.add_argument('-o', '--output-dir', type=str,
                        help='Directory to store output files')
    
    return parser.parse_args()

def main():
    """Main entry point for PyGuard"""
    args = parse_args()
    
    # Load configuration
    config_path = Path(args.config)
    config = Config(config_path)
    
    # Override config with command line arguments
    if args.interface:
        config.interface = args.interface
    if args.output_dir:
        config.output_dir = args.output_dir
    
    # Setup logging
    setup_logging(config)
    
    logger.info(f"Starting PyGuard v{config.version}")
    
    # Create capture manager
    capture_manager = CaptureManager(config)
    
    if args.no_gui:
        # Run in headless mode
        try:
            capture_manager.start()
            # Keep running until interrupted
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Received interrupt signal, shutting down...")
        finally:
            capture_manager.stop()
    else:
        # Start GUI
        start_gui(config, capture_manager)
    
    logger.info("PyGuard shutdown complete")
    return 0

if __name__ == "__main__":
    sys.exit(main())