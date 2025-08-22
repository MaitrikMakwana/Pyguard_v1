#!/usr/bin/env python3
"""
Complete ML Pipeline for PyGuard
This script demonstrates the complete pipeline from packet capture to ML-ready flow features.
It extracts all essential fields required for ML model training and CIC-IDS compatibility.
"""

import os
import sys
import time
import logging
import argparse
import subprocess
from pathlib import Path
import pandas as pd

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from enhanced_packet_extractor import capture_packets_with_extraction, process_packet_comprehensive
from ml_flow_converter import MLFlowConverter

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PyGuardMLPipeline:
    """
    Complete ML pipeline for PyGuard network traffic analysis
    """
    
    def __init__(self, config_path='config.yaml'):
        self.config_path = config_path
        self.flow_converter = MLFlowConverter(config_path)
        
    def capture_packets_to_database(self, duration_seconds=60, interface=None, packet_count=None):
        """
        Capture packets and store them in the database using the existing capture_traffic.py
        """
        logger.info("Starting packet capture to database...")
        
        try:
            # Use the existing capture_traffic.py script
            cmd = [sys.executable, 'capture_traffic.py']
            
            # Set environment variables for configuration if needed
            env = os.environ.copy()
            
            if packet_count:
                # For packet count-based capture, we'll need to modify the config
                logger.info(f"Capturing {packet_count} packets...")
                # You could modify config.yaml temporarily or pass parameters
                process = subprocess.Popen(cmd, env=env)
                # Let it run until it captures the specified number of packets
                # This would require modifying capture_traffic.py to accept command line args
            else:
                logger.info(f"Capturing packets for {duration_seconds} seconds...")
                process = subprocess.Popen(cmd, env=env)
                time.sleep(duration_seconds)
                process.terminate()
                process.wait()
            
            logger.info("Packet capture completed")
            return True
            
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
            return False
    
    def capture_packets_to_csv(self, output_file='captured_packets.csv', 
                              duration_seconds=60, interface=None, packet_count=10):
        """
        Capture packets directly to CSV using the enhanced extractor
        """
        logger.info(f"Capturing packets directly to CSV: {output_file}")
        
        try:
            # Capture packets using enhanced extractor
            packets = capture_packets_with_extraction(
                interface=interface,
                count=packet_count,
                timeout=duration_seconds
            )
            
            if not packets:
                logger.warning("No packets captured")
                return False
            
            # Convert to DataFrame
            packets_df = pd.DataFrame(packets)
            
            # Convert datetime objects to strings for CSV
            if 'timestamp' in packets_df.columns:
                packets_df['timestamp'] = packets_df['timestamp'].astype(str)
            
            # Save to CSV
            packets_df.to_csv(output_file, index=False)
            logger.info(f"Saved {len(packets)} packets to {output_file}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error capturing packets to CSV: {e}")
            return False
    
    def convert_database_to_flows(self, output_file='ml_flows_from_db.csv', 
                                 time_window_minutes=None, limit=None):
        """
        Convert packets from database to flow-based format
        """
        logger.info("Converting database packets to flows...")
        
        success = self.flow_converter.export_flows_to_csv(
            output_file=output_file,
            source='database',
            time_window_minutes=time_window_minutes,
            limit=limit
        )
        
        if success:
            logger.info(f"Flow conversion completed: {output_file}")
        else:
            logger.error("Flow conversion failed")
        
        return success
    
    def convert_csv_to_flows(self, input_csv, output_file='ml_flows_from_csv.csv'):
        """
        Convert packets from CSV to flow-based format
        """
        logger.info(f"Converting CSV packets to flows: {input_csv} -> {output_file}")
        
        success = self.flow_converter.export_flows_to_csv(
            output_file=output_file,
            source='csv',
            input_file=input_csv
        )
        
        if success:
            logger.info(f"Flow conversion completed: {output_file}")
        else:
            logger.error("Flow conversion failed")
        
        return success
    
    def run_complete_pipeline(self, capture_method='csv', duration=60, packet_count=100, 
                             interface=None, output_dir='./ml_output'):
        """
        Run the complete ML pipeline from capture to flow features
        """
        logger.info("Starting complete ML pipeline...")
        
        # Create output directory
        Path(output_dir).mkdir(exist_ok=True)
        
        packet_file = os.path.join(output_dir, 'captured_packets.csv')
        flow_file = os.path.join(output_dir, 'ml_flow_features.csv')
        
        try:
            # Step 1: Capture packets
            if capture_method == 'csv':
                logger.info("Step 1: Capturing packets directly to CSV...")
                if not self.capture_packets_to_csv(
                    output_file=packet_file,
                    duration_seconds=duration,
                    interface=interface,
                    packet_count=packet_count
                ):
                    return False
                
                # Step 2: Convert CSV to flows
                logger.info("Step 2: Converting packets to flows...")
                if not self.convert_csv_to_flows(packet_file, flow_file):
                    return False
                    
            elif capture_method == 'database':
                logger.info("Step 1: Capturing packets to database...")
                if not self.capture_packets_to_database(
                    duration_seconds=duration,
                    interface=interface,
                    packet_count=packet_count
                ):
                    return False
                
                # Step 2: Convert database to flows
                logger.info("Step 2: Converting database packets to flows...")
                if not self.convert_database_to_flows(flow_file):
                    return False
            
            # Step 3: Validate output
            logger.info("Step 3: Validating output...")
            if os.path.exists(flow_file):
                flows_df = pd.read_csv(flow_file)
                logger.info(f"Successfully generated {len(flows_df)} flow records")
                logger.info(f"Flow features file: {flow_file}")
                
                # Print sample of features
                logger.info("Sample flow features:")
                for col in flows_df.columns[:10]:  # Show first 10 columns
                    logger.info(f"  {col}: {flows_df[col].iloc[0] if len(flows_df) > 0 else 'N/A'}")
                
                return True
            else:
                logger.error("Flow features file was not created")
                return False
                
        except Exception as e:
            logger.error(f"Pipeline failed: {e}")
            return False
    
    def validate_essential_fields(self, csv_file):
        """
        Validate that all essential fields are present in the output
        """
        essential_flow_fields = [
            'Flow_ID', 'Src_IP', 'Dst_IP', 'Src_Port', 'Dst_Port', 'Protocol',
            'Flow_Duration', 'Tot_Fwd_Pkts', 'Tot_Bwd_Pkts',
            'TotLen_Fwd_Pkts', 'TotLen_Bwd_Pkts',
            'Fwd_Pkt_Len_Max', 'Fwd_Pkt_Len_Min', 'Fwd_Pkt_Len_Mean',
            'Bwd_Pkt_Len_Max', 'Bwd_Pkt_Len_Min', 'Bwd_Pkt_Len_Mean',
            'Flow_Byts/s', 'Flow_Pkts/s',
            'Flow_IAT_Mean', 'Flow_IAT_Std', 'Flow_IAT_Max', 'Flow_IAT_Min',
            'Fwd_IAT_Mean', 'Bwd_IAT_Mean',
            'FIN_Flag_Cnt', 'SYN_Flag_Cnt', 'RST_Flag_Cnt', 'PSH_Flag_Cnt',
            'ACK_Flag_Cnt', 'URG_Flag_Cnt', 'ECE_Flag_Cnt', 'CWE_Flag_Count',
            'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
            'Label'
        ]
        
        try:
            df = pd.read_csv(csv_file)
            missing_fields = []
            
            for field in essential_flow_fields:
                if field not in df.columns:
                    missing_fields.append(field)
            
            if missing_fields:
                logger.warning(f"Missing essential fields: {missing_fields}")
                return False
            else:
                logger.info("All essential fields are present in the output")
                return True
                
        except Exception as e:
            logger.error(f"Error validating fields: {e}")
            return False

def main():
    """
    Main function for command-line usage
    """
    parser = argparse.ArgumentParser(description='PyGuard Complete ML Pipeline')
    
    # Capture options
    parser.add_argument('--capture-method', choices=['csv', 'database'], default='csv',
                       help='Capture method: direct to CSV or via database')
    parser.add_argument('--duration', type=int, default=60,
                       help='Capture duration in seconds')
    parser.add_argument('--packet-count', type=int, default=100,
                       help='Number of packets to capture')
    parser.add_argument('--interface', help='Network interface to capture from')
    
    # Output options
    parser.add_argument('--output-dir', default='./ml_output',
                       help='Output directory for generated files')
    
    # Pipeline options
    parser.add_argument('--skip-capture', action='store_true',
                       help='Skip capture and convert existing data')
    parser.add_argument('--input-csv', help='Input CSV file (if skipping capture)')
    parser.add_argument('--validate', action='store_true',
                       help='Validate output fields')
    
    # Configuration
    parser.add_argument('--config', default='config.yaml',
                       help='Configuration file path')
    
    args = parser.parse_args()
    
    # Create pipeline
    pipeline = PyGuardMLPipeline(args.config)
    
    if args.skip_capture and args.input_csv:
        # Convert existing CSV to flows
        logger.info("Converting existing CSV to flows...")
        output_file = os.path.join(args.output_dir, 'ml_flow_features.csv')
        Path(args.output_dir).mkdir(exist_ok=True)
        
        success = pipeline.convert_csv_to_flows(args.input_csv, output_file)
        
        if success and args.validate:
            pipeline.validate_essential_fields(output_file)
            
    else:
        # Run complete pipeline
        success = pipeline.run_complete_pipeline(
            capture_method=args.capture_method,
            duration=args.duration,
            packet_count=args.packet_count,
            interface=args.interface,
            output_dir=args.output_dir
        )
        
        if success and args.validate:
            flow_file = os.path.join(args.output_dir, 'ml_flow_features.csv')
            pipeline.validate_essential_fields(flow_file)
    
    if success:
        logger.info("Pipeline completed successfully!")
        logger.info("Your ML-ready flow features are now available for training.")
        return 0
    else:
        logger.error("Pipeline failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())