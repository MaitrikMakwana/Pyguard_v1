#!/usr/bin/env python3
"""
PyGuard Packet Capture to CSV
This script captures network packets and saves them directly to CSV format
with all essential fields required for flow analysis and ML processing.
"""

import os
import sys
import time
import logging
import yaml
import pandas as pd
import json
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, DNS, ARP, Raw
from pathlib import Path
import argparse

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PacketCaptureToCSV:
    """
    Captures network packets and saves them to CSV format with comprehensive fields
    """
    
    def __init__(self, config_path='config.yaml'):
        self.config = self.load_config(config_path)
        self.captured_packets = []
        self.packet_count = 0
        
    def load_config(self, config_path):
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return {}
    
    def extract_packet_info(self, packet):
        """
        Extract comprehensive packet information for CSV export
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict: Packet information dictionary with all essential fields
        """
        # Initialize packet data with all essential fields
        packet_data = {
            # Timing information
            'timestamp': None,
            'timestamp_epoch': None,
            
            # Basic packet information
            'packet_id': self.packet_count,
            'packet_size': len(packet),
            'packet_length': len(packet),
            'capture_length': len(packet),
            
            # Network Layer (IP)
            'src_ip': None,
            'dst_ip': None,
            'protocol': 0,
            'ip_version': None,
            'total_length': 0,
            'ttl': 0,
            'header_length': 0,
            'ip_id': 0,
            'ip_flags': 0,
            'fragment_offset': 0,
            
            # Transport Layer
            'src_port': 0,
            'dst_port': 0,
            'transport_header_length': 0,
            
            # TCP-specific fields
            'tcp_seq': 0,
            'tcp_ack': 0,
            'window_size': 0,
            'tcp_flags_raw': 0,
            
            # Individual TCP flags
            'fin_flag': 0,
            'syn_flag': 0,
            'rst_flag': 0,
            'psh_flag': 0,
            'ack_flag': 0,
            'urg_flag': 0,
            'ece_flag': 0,
            'cwr_flag': 0,
            
            # UDP-specific fields
            'udp_length': 0,
            
            # ICMP-specific fields
            'icmp_type': None,
            'icmp_code': None,
            
            # Payload information
            'payload_size': 0,
            'has_payload': False,
            
            # Protocol identification
            'protocol_name': 'UNKNOWN',
            
            # Ethernet layer
            'mac_src': None,
            'mac_dst': None,
            'eth_type': None,
            
            # Flow direction
            'direction': 'unknown',
            
            # Application layer hints
            'is_http': False,
            'is_https': False,
            'is_dns': False,
            'is_ftp': False,
            'is_ssh': False,
            'is_telnet': False,
            
            # Additional fields for analysis
            'tcp_flags_string': '',
            'flow_key': '',
            'is_fragmented': False,
            'checksum_valid': True
        }
        
        try:
            # Extract timing information
            if hasattr(packet, 'time') and packet.time:
                packet_data['timestamp_epoch'] = packet.time
                packet_data['timestamp'] = datetime.fromtimestamp(packet.time).isoformat()
            else:
                packet_data['timestamp_epoch'] = time.time()
                packet_data['timestamp'] = datetime.now().isoformat()
            
            # Extract Ethernet information
            if Ether in packet:
                packet_data['mac_src'] = packet[Ether].src
                packet_data['mac_dst'] = packet[Ether].dst
                packet_data['eth_type'] = packet[Ether].type
            
            # Extract IP layer information
            if IP in packet:
                packet_data['src_ip'] = packet[IP].src
                packet_data['dst_ip'] = packet[IP].dst
                packet_data['protocol'] = packet[IP].proto
                packet_data['ip_version'] = packet[IP].version
                packet_data['total_length'] = packet[IP].len
                packet_data['ttl'] = packet[IP].ttl
                packet_data['header_length'] = packet[IP].ihl * 4
                packet_data['ip_id'] = packet[IP].id
                packet_data['ip_flags'] = packet[IP].flags.value
                packet_data['fragment_offset'] = packet[IP].frag
                packet_data['is_fragmented'] = packet[IP].frag > 0 or (packet[IP].flags.value & 0x1) != 0
                
                # Create flow key for grouping
                flow_key_parts = [
                    packet_data['src_ip'],
                    packet_data['dst_ip'],
                    str(packet_data['protocol'])
                ]
                
                # Extract transport layer information
                if TCP in packet:
                    packet_data['protocol_name'] = 'TCP'
                    packet_data['src_port'] = packet[TCP].sport
                    packet_data['dst_port'] = packet[TCP].dport
                    packet_data['transport_header_length'] = packet[TCP].dataofs * 4
                    packet_data['tcp_seq'] = packet[TCP].seq
                    packet_data['tcp_ack'] = packet[TCP].ack
                    packet_data['window_size'] = packet[TCP].window
                    packet_data['tcp_flags_raw'] = packet[TCP].flags.value
                    
                    # Extract individual TCP flags
                    packet_data['fin_flag'] = int(packet[TCP].flags.F)
                    packet_data['syn_flag'] = int(packet[TCP].flags.S)
                    packet_data['rst_flag'] = int(packet[TCP].flags.R)
                    packet_data['psh_flag'] = int(packet[TCP].flags.P)
                    packet_data['ack_flag'] = int(packet[TCP].flags.A)
                    packet_data['urg_flag'] = int(packet[TCP].flags.U)
                    packet_data['ece_flag'] = int(packet[TCP].flags.E)
                    packet_data['cwr_flag'] = int(packet[TCP].flags.C)
                    
                    # Create TCP flags string
                    flags = []
                    if packet[TCP].flags.S: flags.append('SYN')
                    if packet[TCP].flags.A: flags.append('ACK')
                    if packet[TCP].flags.F: flags.append('FIN')
                    if packet[TCP].flags.R: flags.append('RST')
                    if packet[TCP].flags.P: flags.append('PSH')
                    if packet[TCP].flags.U: flags.append('URG')
                    if packet[TCP].flags.E: flags.append('ECE')
                    if packet[TCP].flags.C: flags.append('CWR')
                    packet_data['tcp_flags_string'] = '|'.join(flags)
                    
                    # Add ports to flow key
                    flow_key_parts.extend([str(packet_data['src_port']), str(packet_data['dst_port'])])
                    
                    # Detect application protocols by port
                    self.detect_application_protocol(packet_data)
                    
                elif UDP in packet:
                    packet_data['protocol_name'] = 'UDP'
                    packet_data['src_port'] = packet[UDP].sport
                    packet_data['dst_port'] = packet[UDP].dport
                    packet_data['transport_header_length'] = 8
                    packet_data['udp_length'] = packet[UDP].len
                    
                    # Add ports to flow key
                    flow_key_parts.extend([str(packet_data['src_port']), str(packet_data['dst_port'])])
                    
                    # Detect application protocols
                    self.detect_application_protocol(packet_data)
                    
                    # Check for DNS
                    if DNS in packet:
                        packet_data['is_dns'] = True
                    
                elif ICMP in packet:
                    packet_data['protocol_name'] = 'ICMP'
                    packet_data['icmp_type'] = packet[ICMP].type
                    packet_data['icmp_code'] = packet[ICMP].code
                    packet_data['transport_header_length'] = 8
                
                # Calculate payload size
                total_header_length = packet_data['header_length'] + packet_data['transport_header_length']
                packet_data['payload_size'] = packet_data['total_length'] - total_header_length
                if packet_data['payload_size'] < 0:
                    packet_data['payload_size'] = 0
                
                # Check if packet has payload
                packet_data['has_payload'] = packet_data['payload_size'] > 0 or Raw in packet
                
                # If Raw layer exists, use its length (more accurate)
                if Raw in packet:
                    packet_data['payload_size'] = len(packet[Raw].load)
                    packet_data['has_payload'] = True
                
                # Create flow key
                packet_data['flow_key'] = ':'.join(flow_key_parts)
                
                # Determine packet direction
                packet_data['direction'] = self.determine_direction(packet_data['src_ip'])
            
            # Handle ARP packets
            elif ARP in packet:
                packet_data['protocol_name'] = 'ARP'
                packet_data['src_ip'] = packet[ARP].psrc
                packet_data['dst_ip'] = packet[ARP].pdst
                packet_data['protocol'] = 0  # ARP doesn't use IP protocol numbers
                packet_data['flow_key'] = f"{packet_data['src_ip']}:{packet_data['dst_ip']}:ARP"
            
            return packet_data
            
        except Exception as e:
            logger.warning(f"Error extracting packet info: {e}")
            return packet_data
    
    def detect_application_protocol(self, packet_data):
        """
        Detect application layer protocol based on port numbers
        """
        src_port = packet_data['src_port']
        dst_port = packet_data['dst_port']
        
        # HTTP
        if src_port in [80, 8080] or dst_port in [80, 8080]:
            packet_data['is_http'] = True
        
        # HTTPS
        if src_port == 443 or dst_port == 443:
            packet_data['is_https'] = True
        
        # DNS
        if src_port == 53 or dst_port == 53:
            packet_data['is_dns'] = True
        
        # FTP
        if src_port in [20, 21] or dst_port in [20, 21]:
            packet_data['is_ftp'] = True
        
        # SSH
        if src_port == 22 or dst_port == 22:
            packet_data['is_ssh'] = True
        
        # Telnet
        if src_port == 23 or dst_port == 23:
            packet_data['is_telnet'] = True
    
    def determine_direction(self, src_ip):
        """
        Determine packet direction based on source IP
        """
        # Check if source IP is private (RFC 1918)
        if (src_ip.startswith('10.') or 
            src_ip.startswith('172.16.') or src_ip.startswith('172.17.') or 
            src_ip.startswith('172.18.') or src_ip.startswith('172.19.') or 
            src_ip.startswith('172.2') or src_ip.startswith('172.30.') or 
            src_ip.startswith('172.31.') or 
            src_ip.startswith('192.168.') or
            src_ip == '127.0.0.1'):
            return 'outgoing'
        else:
            return 'incoming'
    
    def packet_handler(self, packet):
        """
        Handle captured packets
        """
        self.packet_count += 1
        
        # Extract packet information
        packet_info = self.extract_packet_info(packet)
        self.captured_packets.append(packet_info)
        
        # Log progress
        if self.packet_count % 1000 == 0:
            logger.info(f"Captured {self.packet_count} packets...")
        
        # Print packet summary
        if packet_info['src_ip'] and packet_info['dst_ip']:
            logger.debug(f"Packet {self.packet_count}: {packet_info['protocol_name']} "
                        f"{packet_info['src_ip']}:{packet_info['src_port']} -> "
                        f"{packet_info['dst_ip']}:{packet_info['dst_port']} "
                        f"({packet_info['packet_size']} bytes)")
    
    def capture_packets(self, interface=None, count=0, timeout=None, filter_expr=""):
        """
        Capture packets from network interface
        
        Args:
            interface: Network interface to capture from
            count: Number of packets to capture (0 for unlimited)
            timeout: Capture timeout in seconds
            filter_expr: BPF filter expression
        """
        logger.info("Starting packet capture...")
        
        if interface:
            logger.info(f"Interface: {interface}")
        if count > 0:
            logger.info(f"Packet count: {count}")
        if timeout:
            logger.info(f"Timeout: {timeout} seconds")
        if filter_expr:
            logger.info(f"Filter: {filter_expr}")
        
        try:
            # Start packet capture
            sniff(
                iface=interface,
                prn=self.packet_handler,
                count=count,
                timeout=timeout,
                filter=filter_expr,
                store=0  # Don't store packets in memory
            )
            
            logger.info(f"Capture completed. Processed {self.packet_count} packets")
            
        except KeyboardInterrupt:
            logger.info("Capture interrupted by user")
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
            raise
    
    def save_to_csv(self, output_file, include_raw_data=False):
        """
        Save captured packets to CSV file
        
        Args:
            output_file: Path to output CSV file
            include_raw_data: Whether to include raw packet data
        """
        if not self.captured_packets:
            logger.warning("No packets to save")
            return False
        
        try:
            # Create DataFrame
            df = pd.DataFrame(self.captured_packets)
            
            # Sort columns for better organization
            id_cols = ['packet_id', 'timestamp', 'timestamp_epoch']
            network_cols = ['src_ip', 'dst_ip', 'protocol', 'protocol_name', 'ip_version']
            transport_cols = ['src_port', 'dst_port', 'tcp_seq', 'tcp_ack', 'window_size']
            size_cols = ['packet_size', 'total_length', 'header_length', 'payload_size']
            flag_cols = [col for col in df.columns if 'flag' in col.lower()]
            app_cols = [col for col in df.columns if col.startswith('is_')]
            other_cols = [col for col in df.columns if col not in 
                         id_cols + network_cols + transport_cols + size_cols + flag_cols + app_cols]
            
            # Reorder columns
            ordered_cols = (id_cols + network_cols + transport_cols + 
                           size_cols + flag_cols + app_cols + sorted(other_cols))
            
            # Filter columns that exist in the DataFrame
            ordered_cols = [col for col in ordered_cols if col in df.columns]
            df = df[ordered_cols]
            
            # Save to CSV
            df.to_csv(output_file, index=False)
            logger.info(f"Saved {len(df)} packets to {output_file}")
            
            # Print summary
            self.print_capture_summary(df)
            
            return True
            
        except Exception as e:
            logger.error(f"Error saving to CSV: {e}")
            return False
    
    def print_capture_summary(self, df):
        """
        Print summary of captured packets
        """
        logger.info("Capture Summary:")
        logger.info(f"  Total packets: {len(df)}")
        
        # Protocol distribution
        if 'protocol_name' in df.columns:
            protocol_counts = df['protocol_name'].value_counts()
            logger.info("  Protocol distribution:")
            for protocol, count in protocol_counts.head(10).items():
                logger.info(f"    {protocol}: {count}")
        
        # Direction distribution
        if 'direction' in df.columns:
            direction_counts = df['direction'].value_counts()
            logger.info("  Direction distribution:")
            for direction, count in direction_counts.items():
                logger.info(f"    {direction}: {count}")
        
        # Application protocol detection
        app_cols = [col for col in df.columns if col.startswith('is_') and col != 'is_fragmented']
        if app_cols:
            logger.info("  Application protocols detected:")
            for col in app_cols:
                count = df[col].sum()
                if count > 0:
                    protocol_name = col.replace('is_', '').upper()
                    logger.info(f"    {protocol_name}: {count}")
        
        # Size statistics
        if 'packet_size' in df.columns:
            logger.info(f"  Average packet size: {df['packet_size'].mean():.2f} bytes")
            logger.info(f"  Max packet size: {df['packet_size'].max()} bytes")
            logger.info(f"  Min packet size: {df['packet_size'].min()} bytes")

def main():
    """
    Main function for command-line usage
    """
    parser = argparse.ArgumentParser(
        description='Capture network packets and save to CSV format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python capture_to_csv.py -o packets.csv -c 1000
  python capture_to_csv.py -o packets.csv -t 60 --interface eth0
  python capture_to_csv.py -o packets.csv --filter "tcp port 80"
        """
    )
    
    parser.add_argument('-o', '--output', default='captured_packets.csv',
                       help='Output CSV file (default: captured_packets.csv)')
    parser.add_argument('-c', '--count', type=int, default=0,
                       help='Number of packets to capture (0 for unlimited)')
    parser.add_argument('-t', '--timeout', type=int,
                       help='Capture timeout in seconds')
    parser.add_argument('-i', '--interface',
                       help='Network interface to capture from')
    parser.add_argument('-f', '--filter', default='',
                       help='BPF filter expression')
    parser.add_argument('--config', default='config.yaml',
                       help='Configuration file path')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create output directory if needed
    output_dir = os.path.dirname(args.output)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    try:
        # Create capture instance
        capturer = PacketCaptureToCSV(args.config)
        
        # Start capture
        capturer.capture_packets(
            interface=args.interface,
            count=args.count,
            timeout=args.timeout,
            filter_expr=args.filter
        )
        
        # Save to CSV
        success = capturer.save_to_csv(args.output)
        
        if success:
            logger.info(f"Packet capture completed successfully!")
            logger.info(f"CSV file saved: {args.output}")
            logger.info("You can now use this CSV file for flow analysis or ML processing.")
            return 0
        else:
            logger.error("Failed to save CSV file")
            return 1
            
    except KeyboardInterrupt:
        logger.info("Capture interrupted by user")
        return 0
    except Exception as e:
        logger.error(f"Error during packet capture: {e}")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())