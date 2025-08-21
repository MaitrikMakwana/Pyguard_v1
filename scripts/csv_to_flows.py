#!/usr/bin/env python3
"""
CSV to Flow Converter
Converts packet-level CSV data (from Wireshark/Scapy) to flow-based statistics.
Handles bidirectional flows and calculates comprehensive flow metrics.

Input CSV format: frame_num, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, size, summary
Output: Flow-based statistics with forward/backward packet counts and bytes
"""

import pandas as pd
import numpy as np
import argparse
import logging
from datetime import datetime
import os
from pathlib import Path
import json
import yaml

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CSVToFlowConverter:
    """
    Converts packet-level CSV data to flow-based statistics
    """
    
    def __init__(self):
        self.flows_df = None
        self.original_packets = None
        
    def normalize_flow_key(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """
        Create a normalized bidirectional flow key
        Always puts the smaller (IP, port) combination first for consistency
        """
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    
    def parse_timestamp(self, timestamp):
        """
        Convert timestamp to seconds (float)
        Handles various timestamp formats
        """
        if pd.isna(timestamp):
            return 0.0
            
        # If already numeric, return as float
        if isinstance(timestamp, (int, float)):
            return float(timestamp)
        
        # If string, try to parse
        timestamp_str = str(timestamp).strip()
        
        try:
            # Try direct float conversion first (Unix timestamp)
            return float(timestamp_str)
        except ValueError:
            pass
        
        # Try common datetime formats
        datetime_formats = [
            '%Y-%m-%d %H:%M:%S.%f',  # 2023-01-01 12:30:45.123456
            '%Y-%m-%d %H:%M:%S',     # 2023-01-01 12:30:45
            '%m/%d/%Y %H:%M:%S.%f',  # 01/01/2023 12:30:45.123456
            '%m/%d/%Y %H:%M:%S',     # 01/01/2023 12:30:45
            '%d/%m/%Y %H:%M:%S.%f',  # 01/01/2023 12:30:45.123456
            '%d/%m/%Y %H:%M:%S',     # 01/01/2023 12:30:45
        ]
        
        for fmt in datetime_formats:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                return dt.timestamp()
            except ValueError:
                continue
        
        # If all parsing fails, log warning and return 0
        logger.warning(f"Could not parse timestamp: {timestamp}")
        return 0.0
    
    def read_csv_file(self, csv_file):
        """
        Read packet-level CSV file and validate columns
        
        Args:
            csv_file: Path to input CSV file
            
        Returns:
            pandas.DataFrame: Packet data
        """
        logger.info(f"Reading CSV file: {csv_file}")
        
        try:
            # Read CSV file
            df = pd.read_csv(csv_file)
            logger.info(f"Loaded {len(df)} packets from CSV")
            
            # Expected columns
            required_columns = ['timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'size']
            optional_columns = ['frame_num', 'summary']
            
            # Check for required columns
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                logger.error(f"Missing required columns: {missing_columns}")
                logger.info(f"Available columns: {list(df.columns)}")
                raise ValueError(f"Missing required columns: {missing_columns}")
            
            # Add missing optional columns with default values
            for col in optional_columns:
                if col not in df.columns:
                    if col == 'frame_num':
                        df[col] = range(1, len(df) + 1)
                    elif col == 'summary':
                        df[col] = 'Unknown'
            
            # Clean and validate data
            logger.info("Cleaning and validating data...")
            
            # Remove rows with missing essential data
            initial_count = len(df)
            df = df.dropna(subset=['src_ip', 'dst_ip', 'protocol', 'size'])
            if len(df) < initial_count:
                logger.info(f"Removed {initial_count - len(df)} rows with missing essential data")
            
            # Convert data types
            df['src_port'] = pd.to_numeric(df['src_port'], errors='coerce').fillna(0).astype(int)
            df['dst_port'] = pd.to_numeric(df['dst_port'], errors='coerce').fillna(0).astype(int)
            df['size'] = pd.to_numeric(df['size'], errors='coerce').fillna(0).astype(int)
            
            # Parse timestamps
            logger.info("Parsing timestamps...")
            df['timestamp_seconds'] = df['timestamp'].apply(self.parse_timestamp)
            
            # Sort by timestamp for proper flow duration calculation
            df = df.sort_values('timestamp_seconds').reset_index(drop=True)
            
            logger.info(f"Successfully processed {len(df)} packets")
            self.original_packets = df
            return df
            
        except Exception as e:
            logger.error(f"Error reading CSV file: {e}")
            raise
    
    def convert_to_flows(self, packets_df):
        """
        Convert packet-level data to flow-based statistics
        
        Args:
            packets_df: DataFrame with packet data
            
        Returns:
            pandas.DataFrame: Flow-based statistics
        """
        logger.info("Converting packets to flows...")
        
        if packets_df is None or len(packets_df) == 0:
            logger.warning("No packet data to process")
            return pd.DataFrame()
        
        # Create flow key for each packet
        packets_df['flow_key'] = packets_df.apply(
            lambda row: self.normalize_flow_key(
                row['src_ip'], row['dst_ip'], 
                row['src_port'], row['dst_port'], 
                row['protocol']
            ), axis=1
        )
        
        # Group packets by flow
        flows = []
        
        for flow_key, flow_packets in packets_df.groupby('flow_key'):
            flow_stats = self.calculate_flow_statistics(flow_key, flow_packets)
            if flow_stats:
                flows.append(flow_stats)
        
        if not flows:
            logger.warning("No flows generated")
            return pd.DataFrame()
        
        flows_df = pd.DataFrame(flows)
        logger.info(f"Generated {len(flows_df)} flows from {len(packets_df)} packets")
        
        return flows_df
    
    def calculate_flow_statistics(self, flow_key, flow_packets):
        """
        Calculate statistics for a single flow
        
        Args:
            flow_key: Unique flow identifier
            flow_packets: DataFrame with packets belonging to this flow
            
        Returns:
            dict: Flow statistics
        """
        if len(flow_packets) == 0:
            return None
        
        # Sort packets by timestamp
        flow_packets = flow_packets.sort_values('timestamp_seconds')
        
        # Get first packet to determine flow direction
        first_packet = flow_packets.iloc[0]
        flow_src_ip = first_packet['src_ip']
        flow_dst_ip = first_packet['dst_ip']
        flow_src_port = first_packet['src_port']
        flow_dst_port = first_packet['dst_port']
        flow_protocol = first_packet['protocol']
        
        # Separate forward and backward packets
        # Forward: matches the original flow direction (first packet direction)
        forward_mask = (
            (flow_packets['src_ip'] == flow_src_ip) & 
            (flow_packets['dst_ip'] == flow_dst_ip) &
            (flow_packets['src_port'] == flow_src_port) &
            (flow_packets['dst_port'] == flow_dst_port)
        )
        
        forward_packets = flow_packets[forward_mask]
        backward_packets = flow_packets[~forward_mask]
        
        # Calculate packet counts
        total_fwd_packets = len(forward_packets)
        total_bwd_packets = len(backward_packets)
        
        # Calculate byte counts
        total_fwd_bytes = forward_packets['size'].sum() if len(forward_packets) > 0 else 0
        total_bwd_bytes = backward_packets['size'].sum() if len(backward_packets) > 0 else 0
        
        # Calculate flow duration
        if len(flow_packets) > 1:
            first_timestamp = flow_packets['timestamp_seconds'].min()
            last_timestamp = flow_packets['timestamp_seconds'].max()
            flow_duration = last_timestamp - first_timestamp
        else:
            flow_duration = 0.0
        
        # Create flow statistics dictionary
        flow_stats = {
            'src_ip': flow_src_ip,
            'dst_ip': flow_dst_ip,
            'src_port': flow_src_port,
            'dst_port': flow_dst_port,
            'protocol': flow_protocol,
            'total_fwd_packets': total_fwd_packets,
            'total_bwd_packets': total_bwd_packets,
            'flow_duration': round(flow_duration, 6),  # Round to microseconds
            'total_fwd_bytes': int(total_fwd_bytes),
            'total_bwd_bytes': int(total_bwd_bytes),
            
            # Additional useful statistics
            'total_packets': total_fwd_packets + total_bwd_packets,
            'total_bytes': int(total_fwd_bytes + total_bwd_bytes),
            'first_timestamp': flow_packets['timestamp_seconds'].min(),
            'last_timestamp': flow_packets['timestamp_seconds'].max(),
            'flow_key': flow_key
        }
        
        return flow_stats
    
    def save_to_csv(self, flows_df, output_file):
        """
        Save flows to CSV file with exact format requested
        
        Args:
            flows_df: DataFrame with flow statistics
            output_file: Output CSV file path
        """
        if flows_df is None or len(flows_df) == 0:
            logger.warning("No flows to save")
            return False
        
        try:
            # Select only the required columns in the exact order
            output_columns = [
                'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
                'total_fwd_packets', 'total_bwd_packets', 'flow_duration',
                'total_fwd_bytes', 'total_bwd_bytes'
            ]
            
            # Create output DataFrame with only required columns
            output_df = flows_df[output_columns].copy()
            
            # Save to CSV
            output_df.to_csv(output_file, index=False)
            logger.info(f"Saved {len(output_df)} flows to {output_file}")
            
            # Print sample of the output
            logger.info("Sample output:")
            logger.info(output_df.head().to_string(index=False))
            
            return True
            
        except Exception as e:
            logger.error(f"Error saving to CSV: {e}")
            return False
    
    def save_to_json(self, flows_df, output_file):
        """
        Save flows to JSON file
        
        Args:
            flows_df: DataFrame with flow statistics
            output_file: Output JSON file path
        """
        if flows_df is None or len(flows_df) == 0:
            logger.warning("No flows to save to JSON")
            return False
        
        try:
            # Convert DataFrame to JSON
            flows_json = flows_df.to_dict('records')
            
            # Save to JSON file
            with open(output_file, 'w') as f:
                json.dump(flows_json, f, indent=2, default=str)
            
            logger.info(f"Saved {len(flows_json)} flows to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving to JSON: {e}")
            return False
    
    def save_to_database(self, flows_df, config_file='config.yaml'):
        """
        Save flows to PostgreSQL database
        
        Args:
            flows_df: DataFrame with flow statistics
            config_file: Configuration file path
        """
        if flows_df is None or len(flows_df) == 0:
            logger.warning("No flows to save to database")
            return False
        
        try:
            # Load database configuration
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            db_config = config.get('database', {})
            if not db_config.get('enabled', False):
                logger.info("Database storage is disabled in configuration")
                return False
            
            # Import database dependencies
            import psycopg2
            from sqlalchemy import create_engine
            
            # Create database connection
            connection_string = (
                f"postgresql://{db_config['user']}:{db_config['password']}"
                f"@{db_config['host']}:{db_config['port']}/{db_config['name']}"
            )
            
            engine = create_engine(connection_string)
            
            # Save to database table
            table_name = 'flows'
            flows_df.to_sql(table_name, engine, if_exists='append', index=False)
            
            logger.info(f"Saved {len(flows_df)} flows to database table '{table_name}'")
            return True
            
        except ImportError:
            logger.warning("Database dependencies not available (psycopg2, sqlalchemy)")
            return False
        except Exception as e:
            logger.error(f"Error saving to database: {e}")
            return False
    
    def print_flow_summary(self, flows_df):
        """
        Print summary statistics of the flows
        
        Args:
            flows_df: DataFrame with flow statistics
        """
        if flows_df is None or len(flows_df) == 0:
            logger.info("No flows to summarize")
            return
        
        logger.info("Flow Summary Statistics:")
        logger.info(f"  Total flows: {len(flows_df)}")
        
        # Protocol distribution
        if 'protocol' in flows_df.columns:
            protocol_counts = flows_df['protocol'].value_counts()
            logger.info("  Protocol distribution:")
            for protocol, count in protocol_counts.items():
                # Convert protocol number to name
                protocol_names = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
                protocol_name = protocol_names.get(protocol, f'Protocol-{protocol}')
                logger.info(f"    {protocol_name}: {count}")
        
        # Flow duration statistics
        if 'flow_duration' in flows_df.columns:
            avg_duration = flows_df['flow_duration'].mean()
            max_duration = flows_df['flow_duration'].max()
            logger.info(f"  Average flow duration: {avg_duration:.4f} seconds")
            logger.info(f"  Maximum flow duration: {max_duration:.4f} seconds")
        
        # Packet statistics
        if 'total_fwd_packets' in flows_df.columns and 'total_bwd_packets' in flows_df.columns:
            total_packets = flows_df['total_fwd_packets'].sum() + flows_df['total_bwd_packets'].sum()
            avg_packets_per_flow = total_packets / len(flows_df)
            logger.info(f"  Total packets: {total_packets}")
            logger.info(f"  Average packets per flow: {avg_packets_per_flow:.2f}")
        
        # Byte statistics
        if 'total_fwd_bytes' in flows_df.columns and 'total_bwd_bytes' in flows_df.columns:
            total_bytes = flows_df['total_fwd_bytes'].sum() + flows_df['total_bwd_bytes'].sum()
            avg_bytes_per_flow = total_bytes / len(flows_df)
            logger.info(f"  Total bytes: {total_bytes:,}")
            logger.info(f"  Average bytes per flow: {avg_bytes_per_flow:.2f}")
        
        # Bidirectional flow statistics
        bidirectional_flows = flows_df[(flows_df['total_fwd_packets'] > 0) & (flows_df['total_bwd_packets'] > 0)]
        unidirectional_flows = flows_df[(flows_df['total_fwd_packets'] > 0) & (flows_df['total_bwd_packets'] == 0)] | \
                              flows_df[(flows_df['total_fwd_packets'] == 0) & (flows_df['total_bwd_packets'] > 0)]
        
        logger.info(f"  Bidirectional flows: {len(bidirectional_flows)}")
        logger.info(f"  Unidirectional flows: {len(unidirectional_flows)}")

def main():
    """
    Main function for command-line usage
    """
    parser = argparse.ArgumentParser(
        description='Convert packet-level CSV to flow-based statistics',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Input CSV format:
  Required columns: timestamp, src_ip, src_port, dst_ip, dst_port, protocol, size
  Optional columns: frame_num, summary

Output formats:
  CSV: src_ip, dst_ip, src_port, dst_port, protocol, total_fwd_packets, total_bwd_packets, flow_duration, total_fwd_bytes, total_bwd_bytes
  JSON: Same data in JSON format
  Database: Saved to PostgreSQL (if configured)

Examples:
  python csv_to_flows.py packets.csv -o flows.csv
  python csv_to_flows.py packets.csv -o flows.csv --save-all
  python csv_to_flows.py packets.csv -o flows.csv --json flows.json --database
        """
    )
    
    parser.add_argument('input_csv', help='Input CSV file with packet data')
    parser.add_argument('-o', '--output', default='flows.csv',
                       help='Output CSV file (default: flows.csv)')
    parser.add_argument('--json', help='Also save to JSON file')
    parser.add_argument('--database', action='store_true',
                       help='Also save to database (requires config.yaml)')
    parser.add_argument('--save-all', action='store_true',
                       help='Save to all formats (CSV, JSON, Database)')
    parser.add_argument('--config', default='config.yaml',
                       help='Configuration file for database (default: config.yaml)')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate input file
    if not os.path.exists(args.input_csv):
        logger.error(f"Input CSV file not found: {args.input_csv}")
        return 1
    
    # Create output directory if needed
    output_dir = os.path.dirname(args.output)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    try:
        # Create converter
        converter = CSVToFlowConverter()
        
        # Step 1: Read CSV file
        packets_df = converter.read_csv_file(args.input_csv)
        
        # Step 2: Convert to flows
        flows_df = converter.convert_to_flows(packets_df)
        
        if flows_df is None or len(flows_df) == 0:
            logger.error("No flows generated")
            return 1
        
        # Step 3: Save outputs
        success = True
        
        # Always save CSV
        if not converter.save_to_csv(flows_df, args.output):
            success = False
        
        # Save JSON if requested
        if args.json or args.save_all:
            json_file = args.json if args.json else args.output.replace('.csv', '.json')
            if not converter.save_to_json(flows_df, json_file):
                success = False
        
        # Save to database if requested
        if args.database or args.save_all:
            if not converter.save_to_database(flows_df, args.config):
                logger.warning("Database save failed, but continuing...")
        
        # Print summary
        converter.print_flow_summary(flows_df)
        
        if success:
            logger.info("✅ Flow conversion completed successfully!")
            logger.info(f"📁 Output files:")
            logger.info(f"   CSV: {args.output}")
            if args.json or args.save_all:
                json_file = args.json if args.json else args.output.replace('.csv', '.json')
                logger.info(f"   JSON: {json_file}")
            if args.database or args.save_all:
                logger.info(f"   Database: flows table")
            return 0
        else:
            logger.error("❌ Some operations failed")
            return 1
            
    except Exception as e:
        logger.error(f"❌ Flow conversion failed: {e}")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())