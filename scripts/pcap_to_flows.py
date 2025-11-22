#!/usr/bin/env python3
"""
PCAP to Flow Converter for CIC-IDS Format
This script reads .pcap files and converts packet-level data into flow-based statistics
compatible with CIC-IDS dataset format for machine learning analysis.

Author: PyGuard Team
Version: 1.0
"""

import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Ether
from collections import defaultdict
import argparse
import logging
import time
from datetime import datetime
import os
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PcapToFlowConverter:
    """
    Converts PCAP files to flow-based features compatible with CIC-IDS format
    """
    
    def __init__(self):
        self.flows = defaultdict(list)
        self.flow_features = []
        
    def create_flow_key(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """
        Create a unique flow identifier
        Uses bidirectional flow key (smaller IP:port combination first)
        """
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    
    def extract_packet_info(self, packet, packet_time):
        """
        Extract essential information from a single packet
        
        Args:
            packet: Scapy packet object
            packet_time: Packet timestamp
            
        Returns:
            dict: Packet information dictionary
        """
        packet_info = {
            'timestamp': packet_time,
            'packet_size': len(packet),
            'src_ip': None,
            'dst_ip': None,
            'src_port': 0,
            'dst_port': 0,
            'protocol': 0,
            'header_length': 0,
            'payload_size': 0,
            'fin_flag': 0,
            'syn_flag': 0,
            'rst_flag': 0,
            'psh_flag': 0,
            'ack_flag': 0,
            'urg_flag': 0,
            'ece_flag': 0,
            'cwr_flag': 0,
            'window_size': 0,
            'direction': 'forward'  # Will be determined later
        }
        
        try:
            # Extract IP layer information
            if IP in packet:
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst
                packet_info['protocol'] = packet[IP].proto
                packet_info['header_length'] = packet[IP].ihl * 4  # IP header length
                packet_info['total_length'] = packet[IP].len
                
                # Extract transport layer information
                if TCP in packet:
                    packet_info['src_port'] = packet[TCP].sport
                    packet_info['dst_port'] = packet[TCP].dport
                    packet_info['header_length'] += packet[TCP].dataofs * 4  # Add TCP header length
                    packet_info['window_size'] = packet[TCP].window
                    
                    # Extract TCP flags
                    packet_info['fin_flag'] = int(packet[TCP].flags.F)
                    packet_info['syn_flag'] = int(packet[TCP].flags.S)
                    packet_info['rst_flag'] = int(packet[TCP].flags.R)
                    packet_info['psh_flag'] = int(packet[TCP].flags.P)
                    packet_info['ack_flag'] = int(packet[TCP].flags.A)
                    packet_info['urg_flag'] = int(packet[TCP].flags.U)
                    packet_info['ece_flag'] = int(packet[TCP].flags.E)
                    packet_info['cwr_flag'] = int(packet[TCP].flags.C)
                    
                elif UDP in packet:
                    packet_info['src_port'] = packet[UDP].sport
                    packet_info['dst_port'] = packet[UDP].dport
                    packet_info['header_length'] += 8  # UDP header is 8 bytes
                    
                elif ICMP in packet:
                    packet_info['header_length'] += 8  # ICMP header is typically 8 bytes
                
                # Calculate payload size
                packet_info['payload_size'] = packet_info['total_length'] - packet_info['header_length']
                if packet_info['payload_size'] < 0:
                    packet_info['payload_size'] = 0
                    
        except Exception as e:
            logger.warning(f"Error extracting packet info: {e}")
            
        return packet_info
    
    def read_pcap_file(self, pcap_file, max_packets=None):
        """
        Read packets from PCAP file and group them into flows
        
        Args:
            pcap_file: Path to PCAP file
            max_packets: Maximum number of packets to process (None for all)
        """
        logger.info(f"Reading PCAP file: {pcap_file}")
        
        try:
            # Read packets from PCAP file
            packets = rdpcap(pcap_file)
            total_packets = len(packets)
            
            if max_packets:
                packets = packets[:max_packets]
                logger.info(f"Processing {len(packets)} out of {total_packets} packets")
            else:
                logger.info(f"Processing all {total_packets} packets")
            
            # Process each packet
            for i, packet in enumerate(packets):
                if i % 10000 == 0 and i > 0:
                    logger.info(f"Processed {i} packets...")
                
                # Get packet timestamp
                packet_time = float(packet.time) if hasattr(packet, 'time') else time.time()
                
                # Extract packet information
                packet_info = self.extract_packet_info(packet, packet_time)
                
                # Skip packets without IP information
                if not packet_info['src_ip'] or not packet_info['dst_ip']:
                    continue
                
                # Create flow key
                flow_key = self.create_flow_key(
                    packet_info['src_ip'],
                    packet_info['dst_ip'],
                    packet_info['src_port'],
                    packet_info['dst_port'],
                    packet_info['protocol']
                )
                
                # Add packet to flow
                self.flows[flow_key].append(packet_info)
            
            logger.info(f"Created {len(self.flows)} flows from {len(packets)} packets")
            
        except Exception as e:
            logger.error(f"Error reading PCAP file: {e}")
            raise
    
    def calculate_iat_statistics(self, timestamps):
        """
        Calculate Inter-Arrival Time statistics
        
        Args:
            timestamps: List of packet timestamps
            
        Returns:
            dict: IAT statistics
        """
        if len(timestamps) <= 1:
            return {'min': 0, 'max': 0, 'mean': 0, 'std': 0}
        
        # Sort timestamps and calculate differences
        timestamps = sorted(timestamps)
        iats = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        
        if not iats:
            return {'min': 0, 'max': 0, 'mean': 0, 'std': 0}
        
        return {
            'min': float(min(iats)),
            'max': float(max(iats)),
            'mean': float(np.mean(iats)),
            'std': float(np.std(iats))
        }
    
    def calculate_packet_length_statistics(self, packet_sizes):
        """
        Calculate packet length statistics
        
        Args:
            packet_sizes: List of packet sizes
            
        Returns:
            dict: Packet length statistics
        """
        if not packet_sizes:
            return {'min': 0, 'max': 0, 'mean': 0, 'std': 0}
        
        return {
            'min': int(min(packet_sizes)),
            'max': int(max(packet_sizes)),
            'mean': float(np.mean(packet_sizes)),
            'std': float(np.std(packet_sizes))
        }
    
    def determine_packet_direction(self, flow_packets):
        """
        Determine packet direction within a flow
        The first packet determines the forward direction
        
        Args:
            flow_packets: List of packets in the flow
            
        Returns:
            tuple: (forward_packets, backward_packets)
        """
        if not flow_packets:
            return [], []
        
        # First packet determines forward direction
        first_packet = flow_packets[0]
        forward_src = first_packet['src_ip']
        forward_dst = first_packet['dst_ip']
        forward_sport = first_packet['src_port']
        forward_dport = first_packet['dst_port']
        
        forward_packets = []
        backward_packets = []
        
        for packet in flow_packets:
            if (packet['src_ip'] == forward_src and 
                packet['dst_ip'] == forward_dst and
                packet['src_port'] == forward_sport and
                packet['dst_port'] == forward_dport):
                forward_packets.append(packet)
            else:
                backward_packets.append(packet)
        
        return forward_packets, backward_packets
    
    def calculate_flow_features(self, flow_key, flow_packets):
        """
        Calculate comprehensive flow features from packet list
        
        Args:
            flow_key: Unique flow identifier
            flow_packets: List of packets in the flow
            
        Returns:
            dict: Flow features dictionary
        """
        if not flow_packets:
            return {}
        
        # Sort packets by timestamp
        flow_packets = sorted(flow_packets, key=lambda x: x['timestamp'])
        
        # Basic flow information
        first_packet = flow_packets[0]
        last_packet = flow_packets[-1]
        
        # Flow timing
        flow_start_time = first_packet['timestamp']
        flow_end_time = last_packet['timestamp']
        flow_duration = flow_end_time - flow_start_time
        
        # Separate forward and backward packets
        forward_packets, backward_packets = self.determine_packet_direction(flow_packets)
        
        # Calculate packet counts
        total_fwd_packets = len(forward_packets)
        total_bwd_packets = len(backward_packets)
        total_packets = total_fwd_packets + total_bwd_packets
        
        # Calculate byte counts
        total_fwd_bytes = sum(p['packet_size'] for p in forward_packets)
        total_bwd_bytes = sum(p['packet_size'] for p in backward_packets)
        total_bytes = total_fwd_bytes + total_bwd_bytes
        
        # Calculate packet length statistics
        fwd_packet_sizes = [p['packet_size'] for p in forward_packets]
        bwd_packet_sizes = [p['packet_size'] for p in backward_packets]
        all_packet_sizes = [p['packet_size'] for p in flow_packets]
        
        fwd_length_stats = self.calculate_packet_length_statistics(fwd_packet_sizes)
        bwd_length_stats = self.calculate_packet_length_statistics(bwd_packet_sizes)
        flow_length_stats = self.calculate_packet_length_statistics(all_packet_sizes)
        
        # Calculate IAT statistics
        all_timestamps = [p['timestamp'] for p in flow_packets]
        fwd_timestamps = [p['timestamp'] for p in forward_packets]
        bwd_timestamps = [p['timestamp'] for p in backward_packets]
        
        flow_iat_stats = self.calculate_iat_statistics(all_timestamps)
        fwd_iat_stats = self.calculate_iat_statistics(fwd_timestamps)
        bwd_iat_stats = self.calculate_iat_statistics(bwd_timestamps)
        
        # Calculate TCP flag counts
        tcp_flags = {
            'fin_flag_count': sum(p['fin_flag'] for p in flow_packets),
            'syn_flag_count': sum(p['syn_flag'] for p in flow_packets),
            'rst_flag_count': sum(p['rst_flag'] for p in flow_packets),
            'psh_flag_count': sum(p['psh_flag'] for p in flow_packets),
            'ack_flag_count': sum(p['ack_flag'] for p in flow_packets),
            'urg_flag_count': sum(p['urg_flag'] for p in flow_packets),
            'ece_flag_count': sum(p['ece_flag'] for p in flow_packets),
            'cwr_flag_count': sum(p['cwr_flag'] for p in flow_packets)
        }
        
        # Calculate header lengths
        fwd_header_length = sum(p['header_length'] for p in forward_packets)
        bwd_header_length = sum(p['header_length'] for p in backward_packets)
        
        # Calculate minimum segment size forward
        fwd_payload_sizes = [p['payload_size'] for p in forward_packets if p['payload_size'] > 0]
        min_seg_size_forward = min(fwd_payload_sizes) if fwd_payload_sizes else 0
        
        # Calculate flow rates
        flow_bytes_per_sec = total_bytes / flow_duration if flow_duration > 0 else 0
        flow_packets_per_sec = total_packets / flow_duration if flow_duration > 0 else 0
        
        # Build comprehensive feature dictionary
        features = {
            # Flow identification
            'Flow_ID': flow_key,
            'Src_IP': first_packet['src_ip'],
            'Dst_IP': first_packet['dst_ip'],
            'Src_Port': first_packet['src_port'],
            'Dst_Port': first_packet['dst_port'],
            'Protocol': first_packet['protocol'],
            
            # Flow timing
            'Flow_Duration': flow_duration,
            'Flow_Start_Time': datetime.fromtimestamp(flow_start_time).isoformat(),
            'Flow_End_Time': datetime.fromtimestamp(flow_end_time).isoformat(),
            'Timestamp': datetime.fromtimestamp(flow_start_time).isoformat(),
            
            # Packet counts
            'Tot_Fwd_Pkts': total_fwd_packets,
            'Tot_Bwd_Pkts': total_bwd_packets,
            'TotLen_Fwd_Pkts': total_fwd_bytes,
            'TotLen_Bwd_Pkts': total_bwd_bytes,
            
            # Forward packet length statistics
            'Fwd_Pkt_Len_Max': fwd_length_stats['max'],
            'Fwd_Pkt_Len_Min': fwd_length_stats['min'],
            'Fwd_Pkt_Len_Mean': fwd_length_stats['mean'],
            'Fwd_Pkt_Len_Std': fwd_length_stats['std'],
            
            # Backward packet length statistics
            'Bwd_Pkt_Len_Max': bwd_length_stats['max'],
            'Bwd_Pkt_Len_Min': bwd_length_stats['min'],
            'Bwd_Pkt_Len_Mean': bwd_length_stats['mean'],
            'Bwd_Pkt_Len_Std': bwd_length_stats['std'],
            
            # Flow packet length statistics
            'Pkt_Len_Min': flow_length_stats['min'],
            'Pkt_Len_Max': flow_length_stats['max'],
            'Pkt_Len_Mean': flow_length_stats['mean'],
            'Pkt_Len_Std': flow_length_stats['std'],
            'Pkt_Len_Var': float(np.var(all_packet_sizes)) if all_packet_sizes else 0,
            
            # Flow IAT statistics
            'Flow_IAT_Mean': flow_iat_stats['mean'],
            'Flow_IAT_Std': flow_iat_stats['std'],
            'Flow_IAT_Max': flow_iat_stats['max'],
            'Flow_IAT_Min': flow_iat_stats['min'],
            
            # Forward IAT statistics
            'Fwd_IAT_Tot': sum(fwd_timestamps[i] - fwd_timestamps[i-1] for i in range(1, len(fwd_timestamps))) if len(fwd_timestamps) > 1 else 0,
            'Fwd_IAT_Mean': fwd_iat_stats['mean'],
            'Fwd_IAT_Std': fwd_iat_stats['std'],
            'Fwd_IAT_Max': fwd_iat_stats['max'],
            'Fwd_IAT_Min': fwd_iat_stats['min'],
            
            # Backward IAT statistics
            'Bwd_IAT_Tot': sum(bwd_timestamps[i] - bwd_timestamps[i-1] for i in range(1, len(bwd_timestamps))) if len(bwd_timestamps) > 1 else 0,
            'Bwd_IAT_Mean': bwd_iat_stats['mean'],
            'Bwd_IAT_Std': bwd_iat_stats['std'],
            'Bwd_IAT_Max': bwd_iat_stats['max'],
            'Bwd_IAT_Min': bwd_iat_stats['min'],
            
            # TCP flags
            'FIN_Flag_Cnt': tcp_flags['fin_flag_count'],
            'SYN_Flag_Cnt': tcp_flags['syn_flag_count'],
            'RST_Flag_Cnt': tcp_flags['rst_flag_count'],
            'PSH_Flag_Cnt': tcp_flags['psh_flag_count'],
            'ACK_Flag_Cnt': tcp_flags['ack_flag_count'],
            'URG_Flag_Cnt': tcp_flags['urg_flag_count'],
            'ECE_Flag_Cnt': tcp_flags['ece_flag_count'],
            'CWE_Flag_Count': tcp_flags['cwr_flag_count'],
            
            # Header lengths
            'Fwd_Header_Len': fwd_header_length,
            'Bwd_Header_Len': bwd_header_length,
            'Min_Seg_Size_Forward': min_seg_size_forward,
            
            # Flow rates
            'Flow_Byts/s': flow_bytes_per_sec,
            'Flow_Pkts/s': flow_packets_per_sec,
            'Fwd_Pkts/s': total_fwd_packets / flow_duration if flow_duration > 0 else 0,
            'Bwd_Pkts/s': total_bwd_packets / flow_duration if flow_duration > 0 else 0,
            
            # Additional CIC-IDS compatible features
            'Fwd_PSH_Flags': sum(p['psh_flag'] for p in forward_packets),
            'Bwd_PSH_Flags': sum(p['psh_flag'] for p in backward_packets),
            'Fwd_URG_Flags': sum(p['urg_flag'] for p in forward_packets),
            'Bwd_URG_Flags': sum(p['urg_flag'] for p in backward_packets),
            
            # Window size statistics
            'Init_Win_bytes_forward': forward_packets[0]['window_size'] if forward_packets else 0,
            'Init_Win_bytes_backward': backward_packets[0]['window_size'] if backward_packets else 0,
            
            # Segment size statistics
            'Fwd_Seg_Size_Min': min(p['payload_size'] for p in forward_packets) if forward_packets else 0,
            'Fwd_Seg_Size_Avg': np.mean([p['payload_size'] for p in forward_packets]) if forward_packets else 0,
            'Bwd_Seg_Size_Avg': np.mean([p['payload_size'] for p in backward_packets]) if backward_packets else 0,
            
            # Subflow features
            'Subflow_Fwd_Pkts': total_fwd_packets,
            'Subflow_Fwd_Byts': total_fwd_bytes,
            'Subflow_Bwd_Pkts': total_bwd_packets,
            'Subflow_Bwd_Byts': total_bwd_bytes,

            # Additional CIC-IDS features
            'Down/Up_Ratio': total_bwd_packets / total_fwd_packets if total_fwd_packets > 0 else 0,
            'Average_Packet_Size': (total_fwd_bytes + total_bwd_bytes) / (total_fwd_packets + total_bwd_packets) if (total_fwd_packets + total_bwd_packets) > 0 else 0,
            'Avg_Fwd_Segment_Size': np.mean([p['payload_size'] for p in forward_packets]) if forward_packets else 0,
            'Avg_Bwd_Segment_Size': np.mean([p['payload_size'] for p in backward_packets]) if backward_packets else 0,

            # Bulk transfer features (simplified - would need more sophisticated implementation for full CIC compliance)
            'Fwd_Avg_Bytes/Bulk': 0,  # Placeholder - requires bulk transfer detection
            'Fwd_Avg_Packets/Bulk': 0,  # Placeholder
            'Fwd_Avg_Bulk_Rate': 0,     # Placeholder
            'Bwd_Avg_Bytes/Bulk': 0,    # Placeholder
            'Bwd_Avg_Packets/Bulk': 0,  # Placeholder
            'Bwd_Avg_Bulk_Rate': 0,     # Placeholder

            # Active data packets forward
            'act_data_pkt_fwd': len([p for p in forward_packets if p['payload_size'] > 0]),

            # Active/Idle time features (simplified)
            'Active_Mean': flow_duration / 2 if flow_duration > 0 else 0,
            'Active_Std': flow_duration / 4 if flow_duration > 0 else 0,
            'Active_Max': flow_duration,
            'Active_Min': 0,
            'Idle_Mean': 0,
            'Idle_Std': 0,
            'Idle_Max': 0,
            'Idle_Min': 0,

            # Label (default to BENIGN for unsupervised data)
            'Label': 'BENIGN'
        }
        
        return features
    
    def convert_flows_to_features(self):
        """
        Convert all flows to feature vectors
        """
        logger.info(f"Converting {len(self.flows)} flows to features...")
        
        self.flow_features = []
        
        for i, (flow_key, flow_packets) in enumerate(self.flows.items()):
            if i % 1000 == 0 and i > 0:
                logger.info(f"Processed {i} flows...")
            
            features = self.calculate_flow_features(flow_key, flow_packets)
            if features:
                self.flow_features.append(features)
        
        logger.info(f"Generated {len(self.flow_features)} flow feature vectors")
    
    def export_to_csv(self, output_file):
        """
        Export flow features to CSV file in CIC-IDS format

        Args:
            output_file: Path to output CSV file
        """
        if not self.flow_features:
            logger.error("No flow features to export")
            return False

        try:
            # Create DataFrame
            df = pd.DataFrame(self.flow_features)

            # Define exact CIC-IDS column order for ML compatibility
            cic_columns = [
                'Flow_ID', 'Src_IP', 'Src_Port', 'Dst_IP', 'Dst_Port', 'Protocol',
                'Timestamp', 'Flow_Duration', 'Tot_Fwd_Pkts', 'Tot_Bwd_Pkts',
                'TotLen_Fwd_Pkts', 'TotLen_Bwd_Pkts', 'Fwd_Pkt_Len_Max', 'Fwd_Pkt_Len_Min',
                'Fwd_Pkt_Len_Mean', 'Fwd_Pkt_Len_Std', 'Bwd_Pkt_Len_Max', 'Bwd_Pkt_Len_Min',
                'Bwd_Pkt_Len_Mean', 'Bwd_Pkt_Len_Std', 'Flow_Byts/s', 'Flow_Pkts/s',
                'Flow_IAT_Mean', 'Flow_IAT_Std', 'Flow_IAT_Max', 'Flow_IAT_Min',
                'Fwd_IAT_Tot', 'Fwd_IAT_Mean', 'Fwd_IAT_Std', 'Fwd_IAT_Max', 'Fwd_IAT_Min',
                'Bwd_IAT_Tot', 'Bwd_IAT_Mean', 'Bwd_IAT_Std', 'Bwd_IAT_Max', 'Bwd_IAT_Min',
                'Fwd_PSH_Flags', 'Bwd_PSH_Flags', 'Fwd_URG_Flags', 'Bwd_URG_Flags',
                'Fwd_Header_Len', 'Bwd_Header_Len', 'Fwd_Pkts/s', 'Bwd_Pkts/s',
                'Pkt_Len_Min', 'Pkt_Len_Max', 'Pkt_Len_Mean', 'Pkt_Len_Std', 'Pkt_Len_Var',
                'FIN_Flag_Cnt', 'SYN_Flag_Cnt', 'RST_Flag_Cnt', 'PSH_Flag_Cnt',
                'ACK_Flag_Cnt', 'URG_Flag_Cnt', 'CWE_Flag_Count', 'ECE_Flag_Cnt',
                'Down/Up_Ratio', 'Average_Packet_Size', 'Avg_Fwd_Segment_Size', 'Avg_Bwd_Segment_Size',
                'Fwd_Avg_Bytes/Bulk', 'Fwd_Avg_Packets/Bulk', 'Fwd_Avg_Bulk_Rate',
                'Bwd_Avg_Bytes/Bulk', 'Bwd_Avg_Packets/Bulk', 'Bwd_Avg_Bulk_Rate',
                'Subflow_Fwd_Pkts', 'Subflow_Fwd_Byts', 'Subflow_Bwd_Pkts', 'Subflow_Bwd_Byts',
                'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
                'Min_Seg_Size_Forward', 'Active_Mean', 'Active_Std', 'Active_Max', 'Active_Min',
                'Idle_Mean', 'Idle_Std', 'Idle_Max', 'Idle_Min', 'Label'
            ]

            # Ensure all CIC columns exist (add missing ones with default values)
            for col in cic_columns:
                if col not in df.columns:
                    if col in ['Flow_Start_Time', 'Flow_End_Time']:
                        df[col] = ''  # These are optional timing fields
                    else:
                        df[col] = 0  # Default to 0 for numeric features

            # Reorder columns to exact CIC format
            df = df[cic_columns]
            
            # Export to CSV
            df.to_csv(output_file, index=False)
            logger.info(f"Exported {len(df)} flow records to {output_file}")
            
            # Print summary statistics
            self.print_summary_statistics(df)
            
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}")
            return False
    
    def print_summary_statistics(self, df):
        """
        Print summary statistics of the generated flows
        """
        logger.info("Flow Summary Statistics:")
        logger.info(f"  Total flows: {len(df)}")
        
        # Protocol distribution
        if 'Protocol' in df.columns:
            protocol_counts = df['Protocol'].value_counts()
            logger.info("  Protocol distribution:")
            for protocol, count in protocol_counts.items():
                protocol_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(protocol, f'Protocol-{protocol}')
                logger.info(f"    {protocol_name}: {count}")
        
        # Flow duration statistics
        if 'Flow_Duration' in df.columns:
            logger.info(f"  Average flow duration: {df['Flow_Duration'].mean():.4f} seconds")
            logger.info(f"  Max flow duration: {df['Flow_Duration'].max():.4f} seconds")
        
        # Packet statistics
        if 'Tot_Fwd_Pkts' in df.columns and 'Tot_Bwd_Pkts' in df.columns:
            total_packets = df['Tot_Fwd_Pkts'].sum() + df['Tot_Bwd_Pkts'].sum()
            logger.info(f"  Total packets in flows: {total_packets}")
            logger.info(f"  Average packets per flow: {total_packets / len(df):.2f}")
        
        # Byte statistics
        if 'TotLen_Fwd_Pkts' in df.columns and 'TotLen_Bwd_Pkts' in df.columns:
            total_bytes = df['TotLen_Fwd_Pkts'].sum() + df['TotLen_Bwd_Pkts'].sum()
            logger.info(f"  Total bytes in flows: {total_bytes}")
            logger.info(f"  Average bytes per flow: {total_bytes / len(df):.2f}")

def main():
    """
    Main function for command-line usage
    """
    parser = argparse.ArgumentParser(
        description='Convert PCAP files to CIC-IDS format flow features',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pcap_to_flows.py input.pcap -o flows.csv
  python pcap_to_flows.py input.pcap -o flows.csv --max-packets 100000
  python pcap_to_flows.py input.pcap -o flows.csv --verbose
        """
    )
    
    parser.add_argument('pcap_file', help='Input PCAP file path')
    parser.add_argument('-o', '--output', default='flow_features.csv',
                       help='Output CSV file path (default: flow_features.csv)')
    parser.add_argument('--max-packets', type=int,
                       help='Maximum number of packets to process')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate input file
    if not os.path.exists(args.pcap_file):
        logger.error(f"PCAP file not found: {args.pcap_file}")
        return 1
    
    # Create output directory if needed
    output_dir = os.path.dirname(args.output)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    try:
        # Create converter and process PCAP file
        converter = PcapToFlowConverter()
        
        # Step 1: Read PCAP file and group into flows
        start_time = time.time()
        converter.read_pcap_file(args.pcap_file, args.max_packets)
        read_time = time.time() - start_time
        logger.info(f"PCAP reading completed in {read_time:.2f} seconds")
        
        # Step 2: Convert flows to features
        start_time = time.time()
        converter.convert_flows_to_features()
        convert_time = time.time() - start_time
        logger.info(f"Flow feature calculation completed in {convert_time:.2f} seconds")
        
        # Step 3: Export to CSV
        start_time = time.time()
        success = converter.export_to_csv(args.output)
        export_time = time.time() - start_time
        logger.info(f"CSV export completed in {export_time:.2f} seconds")
        
        if success:
            logger.info(f"Successfully converted {args.pcap_file} to {args.output}")
            logger.info("The CSV file is now ready for machine learning analysis!")
            return 0
        else:
            logger.error("Failed to export CSV file")
            return 1
            
    except Exception as e:
        logger.error(f"Error processing PCAP file: {e}")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())