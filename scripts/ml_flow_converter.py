"""
ML Flow Converter for PyGuard
Converts packet-level data to flow-based format compatible with CIC-IDS and other ML datasets.
Ensures all essential fields are properly extracted and formatted for machine learning.
"""

import pandas as pd
import numpy as np
import psycopg2
import yaml
import logging
import json
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MLFlowConverter:
    """
    Converts packet-level data to flow-based format for ML analysis
    """
    
    def __init__(self, config_path='config.yaml'):
        self.config = self.load_config(config_path)
        self.essential_fields = [
            # Network Layer
            'src_ip', 'dst_ip', 'protocol', 'total_length', 'ttl',
            # Transport Layer
            'src_port', 'dst_port', 'packet_size', 'header_length',
            # TCP Flags
            'fin_flag', 'syn_flag', 'rst_flag', 'psh_flag', 
            'ack_flag', 'urg_flag', 'ece_flag', 'cwr_flag',
            # Timing
            'timestamp', 'timestamp_epoch',
            # Window size
            'window_size',
            # Payload
            'payload_size'
        ]
    
    def load_config(self, config_path):
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return None
    
    def create_flow_key(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """Create a unique flow identifier"""
        # Create bidirectional flow key (normalize direction)
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    
    def get_packets_from_database(self, time_window_minutes=None, limit=None):
        """
        Retrieve packet data from PostgreSQL database
        """
        if not self.config or not self.config.get('database'):
            logger.error("Database configuration not found")
            return None
        
        db_config = self.config['database']
        
        try:
            # Connect to database
            conn = psycopg2.connect(
                host=db_config['host'],
                port=db_config['port'],
                dbname=db_config['name'],
                user=db_config['user'],
                password=db_config['password']
            )
            
            # Build query with all essential fields
            query = """
            SELECT 
                timestamp,
                timestamp_epoch,
                src_ip,
                dst_ip,
                protocol,
                total_length,
                ttl,
                src_port,
                dst_port,
                packet_size,
                header_length,
                fin_flag,
                syn_flag,
                rst_flag,
                psh_flag,
                ack_flag,
                urg_flag,
                ece_flag,
                cwr_flag,
                window_size,
                payload_size,
                protocol_name,
                tcp_seq,
                tcp_ack,
                direction,
                ip_version,
                packet_id,
                flags,
                fragment_offset,
                icmp_type,
                icmp_code
            FROM packets 
            WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL
            """
            
            # Add time window filter if specified
            if time_window_minutes:
                query += f" AND timestamp >= NOW() - INTERVAL '{time_window_minutes} minutes'"
            
            # Add limit if specified
            if limit:
                query += f" LIMIT {limit}"
            
            query += " ORDER BY timestamp_epoch"
            
            logger.info("Loading packet data from database...")
            packets_df = pd.read_sql_query(query, conn)
            conn.close()
            
            logger.info(f"Loaded {len(packets_df)} packets from database")
            return packets_df
            
        except Exception as e:
            logger.error(f"Error retrieving packets from database: {e}")
            return None
    
    def load_packets_from_csv(self, csv_file):
        """
        Load packet data from CSV file
        """
        try:
            logger.info(f"Loading packet data from {csv_file}")
            packets_df = pd.read_csv(csv_file)
            logger.info(f"Loaded {len(packets_df)} packets from CSV")
            return packets_df
        except Exception as e:
            logger.error(f"Error loading packets from CSV: {e}")
            return None
    
    def calculate_flow_statistics(self, flow_packets):
        """
        Calculate comprehensive flow statistics from packet list
        """
        if len(flow_packets) == 0:
            return {}
        
        # Convert to DataFrame for easier processing
        flow_df = pd.DataFrame(flow_packets)
        
        # Basic flow information
        first_packet = flow_df.iloc[0]
        last_packet = flow_df.iloc[-1]
        
        # Flow duration
        if len(flow_df) > 1:
            duration = last_packet['timestamp_epoch'] - first_packet['timestamp_epoch']
        else:
            duration = 0
        
        # Separate forward and backward packets
        forward_packets = flow_df[
            (flow_df['src_ip'] == first_packet['src_ip']) & 
            (flow_df['dst_ip'] == first_packet['dst_ip']) &
            (flow_df['src_port'] == first_packet['src_port']) &
            (flow_df['dst_port'] == first_packet['dst_port'])
        ]
        backward_packets = flow_df[
            (flow_df['src_ip'] == first_packet['dst_ip']) & 
            (flow_df['dst_ip'] == first_packet['src_ip']) &
            (flow_df['src_port'] == first_packet['dst_port']) &
            (flow_df['dst_port'] == first_packet['src_port'])
        ]
        
        # Calculate Inter Arrival Time (IAT) statistics
        def calculate_iat_stats(packets_df):
            if len(packets_df) <= 1:
                return {'mean': 0, 'std': 0, 'max': 0, 'min': 0, 'total': 0}
            
            timestamps = packets_df['timestamp_epoch'].sort_values()
            iats = timestamps.diff().dropna()
            
            if len(iats) == 0:
                return {'mean': 0, 'std': 0, 'max': 0, 'min': 0, 'total': 0}
            
            return {
                'mean': float(iats.mean()),
                'std': float(iats.std()) if len(iats) > 1 else 0,
                'max': float(iats.max()),
                'min': float(iats.min()),
                'total': float(iats.sum())
            }
        
        # Calculate packet length statistics
        def calculate_length_stats(packets_df, column='total_length'):
            if len(packets_df) == 0 or column not in packets_df.columns:
                return {'max': 0, 'min': 0, 'mean': 0, 'std': 0}
            
            lengths = packets_df[column].dropna()
            if len(lengths) == 0:
                return {'max': 0, 'min': 0, 'mean': 0, 'std': 0}
            
            return {
                'max': float(lengths.max()),
                'min': float(lengths.min()),
                'mean': float(lengths.mean()),
                'std': float(lengths.std()) if len(lengths) > 1 else 0
            }
        
        # Calculate flow IAT statistics
        flow_iat = calculate_iat_stats(flow_df)
        fwd_iat = calculate_iat_stats(forward_packets)
        bwd_iat = calculate_iat_stats(backward_packets)
        
        # Calculate packet length statistics
        fwd_len_stats = calculate_length_stats(forward_packets, 'total_length')
        bwd_len_stats = calculate_length_stats(backward_packets, 'total_length')
        flow_len_stats = calculate_length_stats(flow_df, 'total_length')
        
        # Calculate payload statistics
        fwd_payload_stats = calculate_length_stats(forward_packets, 'payload_size')
        bwd_payload_stats = calculate_length_stats(backward_packets, 'payload_size')
        
        # Build comprehensive feature set
        features = {
            # Flow identification
            'Flow_ID': f"{first_packet['src_ip']}:{first_packet.get('src_port', 0)}-{first_packet['dst_ip']}:{first_packet.get('dst_port', 0)}-{first_packet.get('protocol', 0)}",
            'Src_IP': first_packet['src_ip'],
            'Src_Port': int(first_packet.get('src_port', 0)),
            'Dst_IP': first_packet['dst_ip'],
            'Dst_Port': int(first_packet.get('dst_port', 0)),
            'Protocol': int(first_packet.get('protocol', 0)),
            'Timestamp': first_packet['timestamp'],
            
            # Flow duration and basic counts
            'Flow_Duration': duration,
            'Tot_Fwd_Pkts': len(forward_packets),
            'Tot_Bwd_Pkts': len(backward_packets),
            'TotLen_Fwd_Pkts': int(forward_packets['total_length'].sum()) if 'total_length' in forward_packets.columns else 0,
            'TotLen_Bwd_Pkts': int(backward_packets['total_length'].sum()) if 'total_length' in backward_packets.columns else 0,
            
            # Packet length statistics - Forward
            'Fwd_Pkt_Len_Max': fwd_len_stats['max'],
            'Fwd_Pkt_Len_Min': fwd_len_stats['min'],
            'Fwd_Pkt_Len_Mean': fwd_len_stats['mean'],
            'Fwd_Pkt_Len_Std': fwd_len_stats['std'],
            
            # Packet length statistics - Backward
            'Bwd_Pkt_Len_Max': bwd_len_stats['max'],
            'Bwd_Pkt_Len_Min': bwd_len_stats['min'],
            'Bwd_Pkt_Len_Mean': bwd_len_stats['mean'],
            'Bwd_Pkt_Len_Std': bwd_len_stats['std'],
            
            # Flow bytes and packets per second
            'Flow_Byts/s': (flow_df['total_length'].sum() / duration) if duration > 0 else 0,
            'Flow_Pkts/s': (len(flow_df) / duration) if duration > 0 else 0,
            
            # Flow IAT statistics
            'Flow_IAT_Mean': flow_iat['mean'],
            'Flow_IAT_Std': flow_iat['std'],
            'Flow_IAT_Max': flow_iat['max'],
            'Flow_IAT_Min': flow_iat['min'],
            
            # Forward IAT statistics
            'Fwd_IAT_Tot': fwd_iat['total'],
            'Fwd_IAT_Mean': fwd_iat['mean'],
            'Fwd_IAT_Std': fwd_iat['std'],
            'Fwd_IAT_Max': fwd_iat['max'],
            'Fwd_IAT_Min': fwd_iat['min'],
            
            # Backward IAT statistics
            'Bwd_IAT_Tot': bwd_iat['total'],
            'Bwd_IAT_Mean': bwd_iat['mean'],
            'Bwd_IAT_Std': bwd_iat['std'],
            'Bwd_IAT_Max': bwd_iat['max'],
            'Bwd_IAT_Min': bwd_iat['min'],
            
            # TCP Flags counts
            'Fwd_PSH_Flags': int(forward_packets['psh_flag'].sum()) if 'psh_flag' in forward_packets.columns else 0,
            'Bwd_PSH_Flags': int(backward_packets['psh_flag'].sum()) if 'psh_flag' in backward_packets.columns else 0,
            'Fwd_URG_Flags': int(forward_packets['urg_flag'].sum()) if 'urg_flag' in forward_packets.columns else 0,
            'Bwd_URG_Flags': int(backward_packets['urg_flag'].sum()) if 'urg_flag' in backward_packets.columns else 0,
            
            # Header lengths
            'Fwd_Header_Len': int(forward_packets['header_length'].sum()) if 'header_length' in forward_packets.columns else 0,
            'Bwd_Header_Len': int(backward_packets['header_length'].sum()) if 'header_length' in backward_packets.columns else 0,
            
            # Packets per second
            'Fwd_Pkts/s': (len(forward_packets) / duration) if duration > 0 else 0,
            'Bwd_Pkts/s': (len(backward_packets) / duration) if duration > 0 else 0,
            
            # Packet length statistics for entire flow
            'Pkt_Len_Min': flow_len_stats['min'],
            'Pkt_Len_Max': flow_len_stats['max'],
            'Pkt_Len_Mean': flow_len_stats['mean'],
            'Pkt_Len_Std': flow_len_stats['std'],
            'Pkt_Len_Var': float(flow_df['total_length'].var()) if 'total_length' in flow_df.columns and len(flow_df) > 1 else 0,
            
            # TCP Window sizes
            'Init_Win_bytes_forward': int(forward_packets['window_size'].iloc[0]) if len(forward_packets) > 0 and 'window_size' in forward_packets.columns else 0,
            'Init_Win_bytes_backward': int(backward_packets['window_size'].iloc[0]) if len(backward_packets) > 0 and 'window_size' in backward_packets.columns else 0,
            
            # TCP Flag counts (total)
            'FIN_Flag_Cnt': int(flow_df['fin_flag'].sum()) if 'fin_flag' in flow_df.columns else 0,
            'SYN_Flag_Cnt': int(flow_df['syn_flag'].sum()) if 'syn_flag' in flow_df.columns else 0,
            'RST_Flag_Cnt': int(flow_df['rst_flag'].sum()) if 'rst_flag' in flow_df.columns else 0,
            'PSH_Flag_Cnt': int(flow_df['psh_flag'].sum()) if 'psh_flag' in flow_df.columns else 0,
            'ACK_Flag_Cnt': int(flow_df['ack_flag'].sum()) if 'ack_flag' in flow_df.columns else 0,
            'URG_Flag_Cnt': int(flow_df['urg_flag'].sum()) if 'urg_flag' in flow_df.columns else 0,
            'CWE_Flag_Count': int(flow_df['cwr_flag'].sum()) if 'cwr_flag' in flow_df.columns else 0,
            'ECE_Flag_Cnt': int(flow_df['ece_flag'].sum()) if 'ece_flag' in flow_df.columns else 0,
            
            # Payload segment sizes
            'Fwd_Seg_Size_Min': fwd_payload_stats['min'],
            'Fwd_Seg_Size_Avg': fwd_payload_stats['mean'],
            'Bwd_Seg_Size_Avg': bwd_payload_stats['mean'],
            
            # Subflow features
            'Subflow_Fwd_Pkts': len(forward_packets),
            'Subflow_Fwd_Byts': int(forward_packets['total_length'].sum()) if 'total_length' in forward_packets.columns else 0,
            'Subflow_Bwd_Pkts': len(backward_packets),
            'Subflow_Bwd_Byts': int(backward_packets['total_length'].sum()) if 'total_length' in backward_packets.columns else 0,
            
            # Active and Idle time features (simplified)
            'Active_Mean': duration / 2 if duration > 0 else 0,
            'Active_Std': duration / 4 if duration > 0 else 0,
            'Active_Max': duration if duration > 0 else 0,
            'Active_Min': 0,
            'Idle_Mean': 0,
            'Idle_Std': 0,
            'Idle_Max': 0,
            'Idle_Min': 0,
            
            # Label (for supervised learning)
            'Label': 'BENIGN'  # Default label, can be changed based on analysis
        }
        
        return features
    
    def convert_packets_to_flows(self, packets_df):
        """
        Convert packet-level data to flow-based features
        """
        if packets_df is None or len(packets_df) == 0:
            logger.warning("No packet data provided")
            return pd.DataFrame()
        
        logger.info(f"Converting {len(packets_df)} packets to flows...")
        
        # Group packets into flows
        flows = defaultdict(list)
        
        for _, packet in packets_df.iterrows():
            # Skip packets without essential IP information
            if pd.isna(packet.get('src_ip')) or pd.isna(packet.get('dst_ip')):
                continue
            
            # Create flow key
            flow_key = self.create_flow_key(
                packet['src_ip'],
                packet['dst_ip'],
                packet.get('src_port', 0),
                packet.get('dst_port', 0),
                packet.get('protocol', 0)
            )
            
            flows[flow_key].append(packet.to_dict())
        
        logger.info(f"Created {len(flows)} flows from packets")
        
        # Calculate flow features
        flow_features = []
        for flow_key, flow_packets in flows.items():
            if len(flow_packets) == 0:
                continue
            
            features = self.calculate_flow_statistics(flow_packets)
            flow_features.append(features)
        
        flows_df = pd.DataFrame(flow_features)
        logger.info(f"Generated {len(flows_df)} flow records with features")
        
        return flows_df
    
    def export_flows_to_csv(self, output_file='ml_flow_features.csv', source='database', 
                           input_file=None, time_window_minutes=None, limit=None):
        """
        Export flow-based features to CSV format for ML analysis
        """
        try:
            # Load packet data
            if source == 'database':
                packets_df = self.get_packets_from_database(time_window_minutes, limit)
            elif source == 'csv' and input_file:
                packets_df = self.load_packets_from_csv(input_file)
            else:
                logger.error("Invalid source or missing input file")
                return False
            
            if packets_df is None or len(packets_df) == 0:
                logger.warning("No packet data available")
                return False
            
            # Convert to flows
            flows_df = self.convert_packets_to_flows(packets_df)
            
            if len(flows_df) == 0:
                logger.warning("No flows generated")
                return False
            
            # Export to CSV
            flows_df.to_csv(output_file, index=False)
            logger.info(f"Exported {len(flows_df)} flows to {output_file}")
            
            # Print summary statistics
            self.print_flow_summary(flows_df)
            
            return True
            
        except Exception as e:
            logger.error(f"Error exporting flows to CSV: {e}")
            return False
    
    def print_flow_summary(self, flows_df):
        """
        Print summary statistics of the generated flows
        """
        logger.info("Flow Summary Statistics:")
        logger.info(f"  Total flows: {len(flows_df)}")
        
        if 'Protocol' in flows_df.columns:
            protocol_counts = flows_df['Protocol'].value_counts()
            logger.info("  Protocol distribution:")
            for protocol, count in protocol_counts.items():
                protocol_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(protocol, f'Protocol-{protocol}')
                logger.info(f"    {protocol_name}: {count}")
        
        if 'Flow_Duration' in flows_df.columns:
            logger.info(f"  Average flow duration: {flows_df['Flow_Duration'].mean():.2f} seconds")
            logger.info(f"  Max flow duration: {flows_df['Flow_Duration'].max():.2f} seconds")
        
        if 'Tot_Fwd_Pkts' in flows_df.columns and 'Tot_Bwd_Pkts' in flows_df.columns:
            total_packets = flows_df['Tot_Fwd_Pkts'].sum() + flows_df['Tot_Bwd_Pkts'].sum()
            logger.info(f"  Total packets in flows: {total_packets}")
            logger.info(f"  Average packets per flow: {total_packets / len(flows_df):.2f}")

def main():
    """
    Main function for command-line usage
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='ML Flow Converter for PyGuard')
    parser.add_argument('--source', choices=['database', 'csv'], default='database',
                       help='Data source (database or csv)')
    parser.add_argument('--input-file', help='Input CSV file (required if source=csv)')
    parser.add_argument('--output-file', default='ml_flow_features.csv',
                       help='Output CSV file for flow features')
    parser.add_argument('--time-window', type=int,
                       help='Time window in minutes (for database source)')
    parser.add_argument('--limit', type=int,
                       help='Limit number of packets to process')
    parser.add_argument('--config', default='config.yaml',
                       help='Configuration file path')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.source == 'csv' and not args.input_file:
        logger.error("Input file is required when source is 'csv'")
        return 1
    
    # Create converter
    converter = MLFlowConverter(args.config)
    
    # Export flows
    success = converter.export_flows_to_csv(
        output_file=args.output_file,
        source=args.source,
        input_file=args.input_file,
        time_window_minutes=args.time_window,
        limit=args.limit
    )
    
    if success:
        logger.info(f"Flow conversion completed successfully!")
        logger.info(f"Output file: {args.output_file}")
        return 0
    else:
        logger.error("Flow conversion failed")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())