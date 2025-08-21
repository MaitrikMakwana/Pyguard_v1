#!/usr/bin/env python3
"""
PyGuard Flow Analysis Runner
This script demonstrates how to capture packets and convert them to flow-based format.
"""

import subprocess
import sys
import time
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def run_packet_capture(duration_seconds=60, packet_count=None):
    """
    Run packet capture for specified duration or packet count
    """
    logger.info(f"Starting packet capture for {duration_seconds} seconds...")
    
    try:
        if packet_count:
            # Run with specific packet count
            process = subprocess.Popen([
                sys.executable, 'capture_traffic.py'
            ])
        else:
            # Run for specific duration
            process = subprocess.Popen([
                sys.executable, 'capture_traffic.py'
            ])
            
            # Wait for specified duration
            time.sleep(duration_seconds)
            process.terminate()
            process.wait()
        
        logger.info("Packet capture completed")
        return True
        
    except Exception as e:
        logger.error(f"Error during packet capture: {e}")
        return False

def export_to_csv():
    """
    Export captured packets to CSV format
    """
    logger.info("Exporting packets to CSV...")
    
    try:
        result = subprocess.run([
            sys.executable, 'capture_traffic.py', '--export-csv', '--output-file', 'captured_packets.csv'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info("Packet export completed successfully")
            return True
        else:
            logger.error(f"Packet export failed: {result.stderr}")
            return False
            
    except Exception as e:
        logger.error(f"Error exporting packets: {e}")
        return False

def convert_to_flows():
    """
    Convert packet data to flow-based format
    """
    logger.info("Converting packets to flow-based format...")
    
    try:
        result = subprocess.run([
            sys.executable, 'flow_analyzer.py', '--output-file', 'flow_features.csv'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info("Flow conversion completed successfully")
            logger.info("Flow features saved to: flow_features.csv")
            return True
        else:
            logger.error(f"Flow conversion failed: {result.stderr}")
            return False
            
    except Exception as e:
        logger.error(f"Error converting to flows: {e}")
        return False

def main():
    """
    Main function to run the complete flow analysis pipeline
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='PyGuard Flow Analysis Pipeline')
    parser.add_argument('--capture-duration', type=int, default=60, 
                       help='Packet capture duration in seconds (default: 60)')
    parser.add_argument('--skip-capture', action='store_true',
                       help='Skip packet capture and use existing data')
    parser.add_argument('--packet-count', type=int,
                       help='Capture specific number of packets instead of time-based')
    
    args = parser.parse_args()
    
    logger.info("Starting PyGuard Flow Analysis Pipeline")
    
    # Step 1: Capture packets (unless skipped)
    if not args.skip_capture:
        if not run_packet_capture(args.capture_duration, args.packet_count):
            logger.error("Packet capture failed")
            return 1
    else:
        logger.info("Skipping packet capture (using existing data)")
    
    # Step 2: Export packets to CSV
    if not export_to_csv():
        logger.error("Packet export failed")
        return 1
    
    # Step 3: Convert to flow-based format
    if not convert_to_flows():
        logger.error("Flow conversion failed")
        return 1
    
    logger.info("Flow analysis pipeline completed successfully!")
    logger.info("Output files:")
    logger.info("  - captured_packets.csv (packet-level data)")
    logger.info("  - flow_features.csv (flow-level data for ML)")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())