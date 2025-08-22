"""
Enhanced Packet Extractor for PyGuard
This module provides comprehensive packet information extraction using Scapy
with all essential fields required for ML model training and CIC-IDS compatibility.
"""

import time
import logging
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, DNS, ARP, Raw
import json

logger = logging.getLogger(__name__)

def extract_basic_packet_info(packet):
    """
    Extract all essential packet information using Scapy
    Returns a dictionary with all fields required for ML analysis
    """
    # Initialize packet info dictionary with default values
    packet_info = {
        # Timing
        'timestamp': None,
        'timestamp_epoch': None,
        
        # Network Layer (IP)
        'src_ip': None,
        'dst_ip': None,
        'protocol': None,  # TCP=6, UDP=17, ICMP=1
        'total_length': 0,
        'ttl': 0,
        'ip_version': None,
        'header_length': 0,
        'packet_id': 0,
        'flags': 0,
        'fragment_offset': 0,
        
        # Transport Layer (TCP/UDP)
        'src_port': 0,
        'dst_port': 0,
        'packet_size': 0,
        
        # TCP-specific fields
        'tcp_header_length': 0,
        'tcp_seq': 0,
        'tcp_ack': 0,
        'window_size': 0,
        
        # TCP Flags (individual flags for ML compatibility)
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
        
        # Flow direction (simplified)
        'direction': 'unknown',
        
        # Additional fields for ML
        'packet_length': 0,
        'capture_length': 0,
    }
    
    try:
        # Extract timing information
        if hasattr(packet, 'time') and packet.time:
            packet_info['timestamp_epoch'] = packet.time
            packet_info['timestamp'] = datetime.fromtimestamp(packet.time)
        else:
            packet_info['timestamp_epoch'] = time.time()
            packet_info['timestamp'] = datetime.now()
        
        # Basic packet size information
        packet_info['packet_size'] = len(packet)
        packet_info['packet_length'] = len(packet)
        packet_info['capture_length'] = len(packet)
        
        # Extract Ethernet information
        if Ether in packet:
            packet_info['mac_src'] = packet[Ether].src
            packet_info['mac_dst'] = packet[Ether].dst
            packet_info['eth_type'] = packet[Ether].type
        
        # Extract IP layer information
        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            packet_info['protocol'] = packet[IP].proto
            packet_info['total_length'] = packet[IP].len
            packet_info['ttl'] = packet[IP].ttl
            packet_info['ip_version'] = packet[IP].version
            packet_info['header_length'] = packet[IP].ihl * 4  # IP header length in bytes
            packet_info['packet_id'] = packet[IP].id
            packet_info['flags'] = packet[IP].flags.value
            packet_info['fragment_offset'] = packet[IP].frag
            
            # Determine protocol and extract transport layer info
            if TCP in packet:
                packet_info['protocol_name'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['tcp_header_length'] = packet[TCP].dataofs * 4
                packet_info['tcp_seq'] = packet[TCP].seq
                packet_info['tcp_ack'] = packet[TCP].ack
                packet_info['window_size'] = packet[TCP].window
                
                # Extract individual TCP flags
                packet_info['fin_flag'] = int(packet[TCP].flags.F)
                packet_info['syn_flag'] = int(packet[TCP].flags.S)
                packet_info['rst_flag'] = int(packet[TCP].flags.R)
                packet_info['psh_flag'] = int(packet[TCP].flags.P)
                packet_info['ack_flag'] = int(packet[TCP].flags.A)
                packet_info['urg_flag'] = int(packet[TCP].flags.U)
                packet_info['ece_flag'] = int(packet[TCP].flags.E)
                packet_info['cwr_flag'] = int(packet[TCP].flags.C)
                
                # Calculate payload size for TCP
                ip_header_len = packet[IP].ihl * 4
                tcp_header_len = packet[TCP].dataofs * 4
                packet_info['payload_size'] = packet_info['total_length'] - ip_header_len - tcp_header_len
                
            elif UDP in packet:
                packet_info['protocol_name'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                packet_info['udp_length'] = packet[UDP].len
                
                # Calculate payload size for UDP
                ip_header_len = packet[IP].ihl * 4
                udp_header_len = 8  # UDP header is always 8 bytes
                packet_info['payload_size'] = packet_info['total_length'] - ip_header_len - udp_header_len
                
            elif ICMP in packet:
                packet_info['protocol_name'] = 'ICMP'
                packet_info['icmp_type'] = packet[ICMP].type
                packet_info['icmp_code'] = packet[ICMP].code
                
                # Calculate payload size for ICMP
                ip_header_len = packet[IP].ihl * 4
                icmp_header_len = 8  # ICMP header is typically 8 bytes
                packet_info['payload_size'] = packet_info['total_length'] - ip_header_len - icmp_header_len
        
        # Handle ARP packets (non-IP)
        elif ARP in packet:
            packet_info['protocol_name'] = 'ARP'
            packet_info['src_ip'] = packet[ARP].psrc
            packet_info['dst_ip'] = packet[ARP].pdst
            packet_info['protocol'] = 0  # ARP doesn't use IP protocol numbers
        
        # Ensure payload size is not negative
        if packet_info['payload_size'] < 0:
            packet_info['payload_size'] = 0
        
        # Check if packet has payload
        packet_info['has_payload'] = packet_info['payload_size'] > 0 or Raw in packet
        
        # If we have Raw layer, use its length as payload size (more accurate)
        if Raw in packet:
            packet_info['payload_size'] = len(packet[Raw].load)
            packet_info['has_payload'] = True
        
        # Determine packet direction (simplified heuristic)
        if packet_info['src_ip']:
            src_ip = packet_info['src_ip']
            # Check if source IP is private (RFC 1918)
            is_private = (
                src_ip.startswith('10.') or 
                src_ip.startswith('172.16.') or src_ip.startswith('172.17.') or 
                src_ip.startswith('172.18.') or src_ip.startswith('172.19.') or 
                src_ip.startswith('172.2') or src_ip.startswith('172.30.') or 
                src_ip.startswith('172.31.') or 
                src_ip.startswith('192.168.') or
                src_ip == '127.0.0.1'
            )
            packet_info['direction'] = 'outgoing' if is_private else 'incoming'
        
        return packet_info
        
    except Exception as e:
        logger.error(f"Error extracting packet info: {e}")
        return packet_info

def extract_application_layer_info(packet, packet_info):
    """
    Extract application layer information (HTTP, DNS, etc.)
    """
    app_info = {}
    
    try:
        # HTTP detection and extraction
        if Raw in packet and packet_info['protocol_name'] == 'TCP':
            # Check for common HTTP ports
            if (packet_info['dst_port'] in [80, 8080, 443, 8443] or 
                packet_info['src_port'] in [80, 8080, 443, 8443]):
                
                try:
                    raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
                    
                    # HTTP Request detection
                    if any(raw_data.startswith(method) for method in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ']):
                        lines = raw_data.split('\r\n')
                        if lines:
                            method, path = lines[0].split(' ')[:2]
                            app_info['http_method'] = method
                            app_info['http_path'] = path
                            
                            # Extract Host header
                            for line in lines[1:]:
                                if line.lower().startswith('host:'):
                                    app_info['http_host'] = line.split(':', 1)[1].strip()
                                    break
                    
                    # HTTP Response detection
                    elif raw_data.startswith('HTTP/'):
                        lines = raw_data.split('\r\n')
                        if lines:
                            status_line = lines[0].split(' ')
                            if len(status_line) >= 2:
                                app_info['http_status_code'] = status_line[1]
                                
                except:
                    pass
        
        # DNS extraction
        if DNS in packet and packet_info['protocol_name'] == 'UDP':
            dns_info = {
                'dns_id': packet[DNS].id,
                'dns_qr': packet[DNS].qr,  # 0 = query, 1 = response
                'dns_opcode': packet[DNS].opcode,
                'dns_rcode': packet[DNS].rcode
            }
            
            # Extract query information
            if packet[DNS].qd and packet[DNS].qr == 0:  # Query
                dns_info['dns_query_name'] = packet[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                dns_info['dns_query_type'] = packet[DNS].qd.qtype
            
            # Extract answer information
            if packet[DNS].an and packet[DNS].qr == 1:  # Response
                answers = []
                for i in range(packet[DNS].ancount):
                    if i < len(packet[DNS].an):
                        try:
                            answer = packet[DNS].an[i]
                            if hasattr(answer, 'rdata'):
                                answers.append(str(answer.rdata))
                        except:
                            pass
                dns_info['dns_answers'] = answers
            
            app_info['dns'] = dns_info
        
        return app_info
        
    except Exception as e:
        logger.error(f"Error extracting application layer info: {e}")
        return app_info

def process_packet_comprehensive(packet):
    """
    Comprehensive packet processing function that extracts all essential information
    """
    # Extract basic packet information
    packet_info = extract_basic_packet_info(packet)
    
    # Extract application layer information
    app_info = extract_application_layer_info(packet, packet_info)
    
    # Merge application layer info
    packet_info.update(app_info)
    
    return packet_info

def capture_packets_with_extraction(interface=None, count=0, timeout=None, filter_expr=""):
    """
    Capture packets and extract comprehensive information
    
    Args:
        interface: Network interface to capture from (None for auto-detect)
        count: Number of packets to capture (0 for unlimited)
        timeout: Capture timeout in seconds (None for no timeout)
        filter_expr: BPF filter expression
    
    Returns:
        List of packet information dictionaries
    """
    captured_packets = []
    
    def packet_handler(packet):
        packet_info = process_packet_comprehensive(packet)
        captured_packets.append(packet_info)
        
        # Log packet info
        logger.info(f"Captured {packet_info['protocol_name']} packet: "
                   f"{packet_info['src_ip']}:{packet_info['src_port']} -> "
                   f"{packet_info['dst_ip']}:{packet_info['dst_port']} "
                   f"({packet_info['packet_size']} bytes)")
    
    try:
        logger.info(f"Starting packet capture...")
        if interface:
            logger.info(f"Interface: {interface}")
        if count > 0:
            logger.info(f"Packet count: {count}")
        if timeout:
            logger.info(f"Timeout: {timeout} seconds")
        if filter_expr:
            logger.info(f"Filter: {filter_expr}")
        
        # Start packet capture
        sniff(
            iface=interface,
            prn=packet_handler,
            count=count,
            timeout=timeout,
            filter=filter_expr,
            store=0  # Don't store packets in memory
        )
        
        logger.info(f"Capture completed. Processed {len(captured_packets)} packets")
        return captured_packets
        
    except Exception as e:
        logger.error(f"Error during packet capture: {e}")
        return captured_packets

# Example usage and testing
if __name__ == "__main__":
    import argparse
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    parser = argparse.ArgumentParser(description='Enhanced Packet Extractor')
    parser.add_argument('--interface', help='Network interface to capture from')
    parser.add_argument('--count', type=int, default=10, help='Number of packets to capture')
    parser.add_argument('--timeout', type=int, help='Capture timeout in seconds')
    parser.add_argument('--filter', default='', help='BPF filter expression')
    parser.add_argument('--output', help='Output JSON file for captured packets')
    
    args = parser.parse_args()
    
    # Capture packets
    packets = capture_packets_with_extraction(
        interface=args.interface,
        count=args.count,
        timeout=args.timeout,
        filter_expr=args.filter
    )
    
    # Save to file if specified
    if args.output and packets:
        import json
        with open(args.output, 'w') as f:
            # Convert datetime objects to strings for JSON serialization
            for packet in packets:
                if packet['timestamp']:
                    packet['timestamp'] = packet['timestamp'].isoformat()
            json.dump(packets, f, indent=2)
        logger.info(f"Saved {len(packets)} packets to {args.output}")
    
    # Print summary
    if packets:
        print(f"\nCaptured {len(packets)} packets")
        print("\nSample packet info:")
        sample = packets[0]
        for key, value in sample.items():
            print(f"  {key}: {value}")