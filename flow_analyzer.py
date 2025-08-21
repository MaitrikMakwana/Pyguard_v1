"""
PyGuard Flow-Based Analysis Script
This script converts packet-level data to flow-based format suitable for ML analysis.
Compatible with CIC-IDS dataset format.
"""

import pandas as pd
import numpy as np
import psycopg2
import yaml
import logging
from datetime import datetime, timedelta
from collections import defaultdict
import json

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_config():
    """Load configuration from config.yaml"""
    try:
        with open('config.yaml', 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return None

def create_flow_key(src_ip, dst_ip, src_port, dst_port, protocol):
    """Create a unique flow identifier"""
    # Normalize flow direction (smaller IP first for bidirectional flows)
    if src_ip < dst_ip:
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
    else:
        return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

def calculate_flow_features(packets_df):
    """
    Calculate flow-based features from packet-level data
    Returns DataFrame with flow-based features compatible with CIC-IDS format
    """
    flows = defaultdict(list)
    
    # Group packets into flows
    for _, packet in packets_df.iterrows():
        if pd.isna(packet['src_ip']) or pd.isna(packet['dst_ip']):
            continue
            
        flow_key = create_flow_key(
            packet['src_ip'], 
            packet['dst_ip'],
            packet.get('src_port', 0),
            packet.get('dst_port', 0),
            packet.get('protocol', 0)
        )
        flows[flow_key].append(packet)
    
    flow_features = []
    
    for flow_key, flow_packets in flows.items():
        if len(flow_packets) == 0:
            continue
            
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
            (flow_df['dst_ip'] == first_packet['dst_ip'])
        ]
        backward_packets = flow_df[
            (flow_df['src_ip'] == first_packet['dst_ip']) & 
            (flow_df['dst_ip'] == first_packet['src_ip'])
        ]
        
        # Calculate features
        features = {
            # Flow identification
            'Flow_ID': flow_key,
            'Src_IP': first_packet['src_ip'],
            'Src_Port': first_packet.get('src_port', 0),
            'Dst_IP': first_packet['dst_ip'],
            'Dst_Port': first_packet.get('dst_port', 0),
            'Protocol': first_packet.get('protocol', 0),
            'Timestamp': first_packet['timestamp'],
            
            # Flow duration and packet counts
            'Flow_Duration': duration,
            'Tot_Fwd_Pkts': len(forward_packets),
            'Tot_Bwd_Pkts': len(backward_packets),
            'TotLen_Fwd_Pkts': forward_packets['total_length'].sum() if 'total_length' in forward_packets.columns else 0,
            'TotLen_Bwd_Pkts': backward_packets['total_length'].sum() if 'total_length' in backward_packets.columns else 0,
            
            # Packet length statistics
            'Fwd_Pkt_Len_Max': forward_packets['total_length'].max() if len(forward_packets) > 0 and 'total_length' in forward_packets.columns else 0,
            'Fwd_Pkt_Len_Min': forward_packets['total_length'].min() if len(forward_packets) > 0 and 'total_length' in forward_packets.columns else 0,
            'Fwd_Pkt_Len_Mean': forward_packets['total_length'].mean() if len(forward_packets) > 0 and 'total_length' in forward_packets.columns else 0,
            'Fwd_Pkt_Len_Std': forward_packets['total_length'].std() if len(forward_packets) > 0 and 'total_length' in forward_packets.columns else 0,
            
            'Bwd_Pkt_Len_Max': backward_packets['total_length'].max() if len(backward_packets) > 0 and 'total_length' in backward_packets.columns else 0,
            'Bwd_Pkt_Len_Min': backward_packets['total_length'].min() if len(backward_packets) > 0 and 'total_length' in backward_packets.columns else 0,
            'Bwd_Pkt_Len_Mean': backward_packets['total_length'].mean() if len(backward_packets) > 0 and 'total_length' in backward_packets.columns else 0,
            'Bwd_Pkt_Len_Std': backward_packets['total_length'].std() if len(backward_packets) > 0 and 'total_length' in backward_packets.columns else 0,
            
            # Flow bytes per second and packets per second
            'Flow_Byts/s': (flow_df['total_length'].sum() / duration) if duration > 0 else 0,
            'Flow_Pkts/s': (len(flow_df) / duration) if duration > 0 else 0,
            
            # Flow IAT (Inter Arrival Time) statistics
            'Flow_IAT_Mean': 0,
            'Flow_IAT_Std': 0,
            'Flow_IAT_Max': 0,
            'Flow_IAT_Min': 0,
            
            # Forward and Backward IAT statistics
            'Fwd_IAT_Tot': 0,
            'Fwd_IAT_Mean': 0,
            'Fwd_IAT_Std': 0,
            'Fwd_IAT_Max': 0,
            'Fwd_IAT_Min': 0,
            
            'Bwd_IAT_Tot': 0,
            'Bwd_IAT_Mean': 0,
            'Bwd_IAT_Std': 0,
            'Bwd_IAT_Max': 0,
            'Bwd_IAT_Min': 0,
            
            # TCP Flags
            'Fwd_PSH_Flags': forward_packets['psh_flag'].sum() if 'psh_flag' in forward_packets.columns else 0,
            'Bwd_PSH_Flags': backward_packets['psh_flag'].sum() if 'psh_flag' in backward_packets.columns else 0,
            'Fwd_URG_Flags': forward_packets['urg_flag'].sum() if 'urg_flag' in forward_packets.columns else 0,
            'Bwd_URG_Flags': backward_packets['urg_flag'].sum() if 'urg_flag' in backward_packets.columns else 0,
            'Fwd_Header_Len': forward_packets['header_length'].sum() if 'header_length' in forward_packets.columns else 0,
            'Bwd_Header_Len': backward_packets['header_length'].sum() if 'header_length' in backward_packets.columns else 0,
            
            # Packets per second
            'Fwd_Pkts/s': (len(forward_packets) / duration) if duration > 0 else 0,
            'Bwd_Pkts/s': (len(backward_packets) / duration) if duration > 0 else 0,
            
            # Packet length statistics for entire flow
            'Pkt_Len_Min': flow_df['total_length'].min() if 'total_length' in flow_df.columns else 0,
            'Pkt_Len_Max': flow_df['total_length'].max() if 'total_length' in flow_df.columns else 0,
            'Pkt_Len_Mean': flow_df['total_length'].mean() if 'total_length' in flow_df.columns else 0,
            'Pkt_Len_Std': flow_df['total_length'].std() if 'total_length' in flow_df.columns else 0,
            'Pkt_Len_Var': flow_df['total_length'].var() if 'total_length' in flow_df.columns else 0,
            
            # TCP Window Size
            'Init_Win_bytes_forward': forward_packets['window_size'].iloc[0] if len(forward_packets) > 0 and 'window_size' in forward_packets.columns else 0,
            'Init_Win_bytes_backward': backward_packets['window_size'].iloc[0] if len(backward_packets) > 0 and 'window_size' in backward_packets.columns else 0,
            
            # Additional TCP flags
            'FIN_Flag_Cnt': flow_df['fin_flag'].sum() if 'fin_flag' in flow_df.columns else 0,
            'SYN_Flag_Cnt': flow_df['syn_flag'].sum() if 'syn_flag' in flow_df.columns else 0,
            'RST_Flag_Cnt': flow_df['rst_flag'].sum() if 'rst_flag' in flow_df.columns else 0,
            'PSH_Flag_Cnt': flow_df['psh_flag'].sum() if 'psh_flag' in flow_df.columns else 0,
            'ACK_Flag_Cnt': flow_df['ack_flag'].sum() if 'ack_flag' in flow_df.columns else 0,
            'URG_Flag_Cnt': flow_df['urg_flag'].sum() if 'urg_flag' in flow_df.columns else 0,
            'CWE_Flag_Count': flow_df['cwr_flag'].sum() if 'cwr_flag' in flow_df.columns else 0,
            'ECE_Flag_Cnt': flow_df['ece_flag'].sum() if 'ece_flag' in flow_df.columns else 0,
            
            # Payload-related features
            'Fwd_Seg_Size_Min': forward_packets['payload_size'].min() if len(forward_packets) > 0 and 'payload_size' in forward_packets.columns else 0,
            'Fwd_Seg_Size_Avg': forward_packets['payload_size'].mean() if len(forward_packets) > 0 and 'payload_size' in forward_packets.columns else 0,
            'Bwd_Seg_Size_Avg': backward_packets['payload_size'].mean() if len(backward_packets) > 0 and 'payload_size' in backward_packets.columns else 0,
            
            # Subflow features
            'Subflow_Fwd_Pkts': len(forward_packets),
            'Subflow_Fwd_Byts': forward_packets['total_length'].sum() if 'total_length' in forward_packets.columns else 0,
            'Subflow_Bwd_Pkts': len(backward_packets),
            'Subflow_Bwd_Byts': backward_packets['total_length'].sum() if 'total_length' in backward_packets.columns else 0,
            
            # Active and Idle time features (simplified)
            'Active_Mean': duration / 2 if duration > 0 else 0,
            'Active_Std': 0,
            'Active_Max': duration if duration > 0 else 0,
            'Active_Min': 0,
            'Idle_Mean': 0,
            'Idle_Std': 0,
            'Idle_Max': 0,
            'Idle_Min': 0,
            
            # Label (for supervised learning - set to BENIGN by default)
            'Label': 'BENIGN'
        }
        
        # Calculate IAT statistics if we have multiple packets
        if len(flow_df) > 1:
            timestamps = flow_df['timestamp_epoch'].sort_values()
            iats = timestamps.diff().dropna()
            
            if len(iats) > 0:
                features['Flow_IAT_Mean'] = iats.mean()
                features['Flow_IAT_Std'] = iats.std()
                features['Flow_IAT_Max'] = iats.max()
                features['Flow_IAT_Min'] = iats.min()
            
            # Forward IAT
            if len(forward_packets) > 1:
                fwd_timestamps = forward_packets['timestamp_epoch'].sort_values()
                fwd_iats = fwd_timestamps.diff().dropna()
                if len(fwd_iats) > 0:
                    features['Fwd_IAT_Tot'] = fwd_iats.sum()
                    features['Fwd_IAT_Mean'] = fwd_iats.mean()
                    features['Fwd_IAT_Std'] = fwd_iats.std()
                    features['Fwd_IAT_Max'] = fwd_iats.max()
                    features['Fwd_IAT_Min'] = fwd_iats.min()
            
            # Backward IAT
            if len(backward_packets) > 1:
                bwd_timestamps = backward_packets['timestamp_epoch'].sort_values()
                bwd_iats = bwd_timestamps.diff().dropna()
                if len(bwd_iats) > 0:
                    features['Bwd_IAT_Tot'] = bwd_iats.sum()
                    features['Bwd_IAT_Mean'] = bwd_iats.mean()
                    features['Bwd_IAT_Std'] = bwd_iats.std()
                    features['Bwd_IAT_Max'] = bwd_iats.max()
                    features['Bwd_IAT_Min'] = bwd_iats.min()
        
        flow_features.append(features)
    
    return pd.DataFrame(flow_features)

def export_flows_to_csv(db_config, output_file='flow_features.csv', time_window_minutes=None):
    """
    Export flow-based features to CSV format
    """
    try:
        # Connect to database
        conn = psycopg2.connect(
            host=db_config['host'],
            port=db_config['port'],
            dbname=db_config['name'],
            user=db_config['user'],
            password=db_config['password']
        )
        
        # Query to get packet data
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
            seq,
            ack
        FROM packets 
        WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL
        ORDER BY timestamp_epoch
        """
        
        # Add time window filter if specified
        if time_window_minutes:
            query += f" AND timestamp >= NOW() - INTERVAL '{time_window_minutes} minutes'"
        
        # Read packet data
        logger.info("Loading packet data from database...")
        packets_df = pd.read_sql_query(query, conn)
        conn.close()
        
        if len(packets_df) == 0:
            logger.warning("No packet data found in database")
            return False
        
        logger.info(f"Loaded {len(packets_df)} packets")
        
        # Convert to flow-based features
        logger.info("Converting packets to flows...")
        flows_df = calculate_flow_features(packets_df)
        
        if len(flows_df) == 0:
            logger.warning("No flows generated from packet data")
            return False
        
        # Export to CSV
        flows_df.to_csv(output_file, index=False)
        logger.info(f"Exported {len(flows_df)} flows to {output_file}")
        
        # Print summary statistics
        logger.info(f"Flow summary:")
        logger.info(f"  - Total flows: {len(flows_df)}")
        logger.info(f"  - Protocols: {flows_df['Protocol'].value_counts().to_dict()}")
        logger.info(f"  - Average flow duration: {flows_df['Flow_Duration'].mean():.2f} seconds")
        logger.info(f"  - Average packets per flow: {(flows_df['Tot_Fwd_Pkts'] + flows_df['Tot_Bwd_Pkts']).mean():.2f}")
        
        return True
        
    except Exception as e:
        logger.error(f"Error exporting flows to CSV: {e}")
        return False

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='PyGuard Flow-Based Analysis')
    parser.add_argument('--output-file', default='flow_features.csv', help='Output CSV file name')
    parser.add_argument('--time-window', type=int, help='Time window in minutes (recent data only)')
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config()
    if not config:
        logger.error("Failed to load configuration")
        return 1
    
    db_config = config.get('database', {})
    
    if export_flows_to_csv(db_config, args.output_file, args.time_window):
        return 0
    else:
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())