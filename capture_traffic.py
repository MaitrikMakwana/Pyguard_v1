"""
PyGuard Network Traffic Capture Script
This script captures network traffic and stores it in the PostgreSQL database.
"""

import os
import sys
import time
import logging
import yaml
import psycopg2
import json
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, DNS, ARP, Raw

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load configuration
def load_config():
    try:
        with open('config.yaml', 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return None

# Process a packet and store it in the database
def process_packet(packet, db_conn, cursor):
    try:
        # Extract basic packet information
        # Use packet timestamp if available, otherwise use current time
        if hasattr(packet, 'time') and packet.time:
            timestamp_epoch = packet.time
            timestamp = datetime.fromtimestamp(packet.time)
        else:
            timestamp = datetime.now()
            timestamp_epoch = time.time()
        
        # Initialize packet data
        packet_data = {
            'timestamp': timestamp,
            'timestamp_epoch': timestamp_epoch,
            'capture_length': len(packet),
            'packet_length': len(packet),
            'packet_size': len(packet),  # Added for compatibility
            'protocol_name': 'UNKNOWN'
        }
        
        # Extract Ethernet information if available
        if Ether in packet:
            packet_data['mac_src'] = packet[Ether].src
            packet_data['mac_dst'] = packet[Ether].dst
            packet_data['eth_type'] = packet[Ether].type
        
        # Extract IP information if available
        if IP in packet:
            packet_data['ip_version'] = packet[IP].version
            packet_data['src_ip'] = packet[IP].src
            packet_data['dst_ip'] = packet[IP].dst
            packet_data['protocol'] = packet[IP].proto
            packet_data['ttl'] = packet[IP].ttl
            packet_data['header_length'] = packet[IP].ihl * 4
            packet_data['total_length'] = packet[IP].len
            packet_data['pkt_id'] = packet[IP].id
            packet_data['flags'] = packet[IP].flags.value
            packet_data['fragment_offset'] = packet[IP].frag
            
            # Determine protocol name
            if TCP in packet:
                packet_data['protocol_name'] = 'TCP'
                packet_data['src_port'] = packet[TCP].sport
                packet_data['dst_port'] = packet[TCP].dport
                packet_data['window_size'] = packet[TCP].window
                packet_data['tcp_flags_raw'] = packet[TCP].flags.value
                packet_data['header_length'] = packet[TCP].dataofs * 4  # TCP header length
                packet_data['tcp_seq'] = packet[TCP].seq
                packet_data['tcp_ack'] = packet[TCP].ack
                
                # Extract individual TCP flags (for ML compatibility)
                packet_data['fin_flag'] = int(packet[TCP].flags.F)
                packet_data['syn_flag'] = int(packet[TCP].flags.S)
                packet_data['rst_flag'] = int(packet[TCP].flags.R)
                packet_data['psh_flag'] = int(packet[TCP].flags.P)
                packet_data['ack_flag'] = int(packet[TCP].flags.A)
                packet_data['urg_flag'] = int(packet[TCP].flags.U)
                packet_data['ece_flag'] = int(packet[TCP].flags.E)
                packet_data['cwr_flag'] = int(packet[TCP].flags.C)
                
                # Extract TCP flags as string list (for backward compatibility)
                flags = []
                if packet[TCP].flags.S:
                    flags.append('SYN')
                if packet[TCP].flags.A:
                    flags.append('ACK')
                if packet[TCP].flags.F:
                    flags.append('FIN')
                if packet[TCP].flags.R:
                    flags.append('RST')
                if packet[TCP].flags.P:
                    flags.append('PSH')
                if packet[TCP].flags.U:
                    flags.append('URG')
                if packet[TCP].flags.E:
                    flags.append('ECE')
                if packet[TCP].flags.C:
                    flags.append('CWR')
                
                packet_data['tcp_flags'] = json.dumps(flags)
                
                # Try to extract HTTP data
                if Raw in packet and (packet_data['dst_port'] == 80 or packet_data['src_port'] == 80 or 
                                     packet_data['dst_port'] == 8080 or packet_data['src_port'] == 8080):
                    try:
                        raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
                        
                        # Simple HTTP request/response detection
                        if raw_data.startswith('GET ') or raw_data.startswith('POST ') or raw_data.startswith('PUT ') or raw_data.startswith('DELETE '):
                            # Extract HTTP method and path
                            method = raw_data.split(' ')[0]
                            path = raw_data.split(' ')[1]
                            
                            # Extract host if available
                            host = None
                            for line in raw_data.split('\r\n'):
                                if line.lower().startswith('host:'):
                                    host = line.split(':', 1)[1].strip()
                                    break
                            
                            http_data = {
                                'type': 'request',
                                'method': method,
                                'path': path,
                                'host': host
                            }
                            packet_data['http'] = json.dumps(http_data)
                        
                        elif raw_data.startswith('HTTP/'):
                            # Extract status code
                            status_line = raw_data.split('\r\n')[0]
                            status_code = status_line.split(' ')[1] if len(status_line.split(' ')) > 1 else None
                            
                            http_data = {
                                'type': 'response',
                                'status_code': status_code
                            }
                            packet_data['http'] = json.dumps(http_data)
                    except:
                        pass
                
            elif UDP in packet:
                packet_data['protocol_name'] = 'UDP'
                packet_data['src_port'] = packet[UDP].sport
                packet_data['dst_port'] = packet[UDP].dport
                packet_data['header_length'] = 8  # UDP header is always 8 bytes
                
                # Try to extract DNS data
                if DNS in packet:
                    dns_data = {
                        'dns_id': packet[DNS].id,
                        'dns_qr': packet[DNS].qr,
                        'dns_query_type': 'response' if packet[DNS].qr == 1 else 'query'
                    }
                    
                    # Extract query name if available
                    if packet[DNS].qd and packet[DNS].qr == 0:
                        dns_data['dns_query_name'] = packet[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                    
                    # Extract answer if available
                    if packet[DNS].an and packet[DNS].qr == 1:
                        answers = []
                        for i in range(packet[DNS].ancount):
                            if i < len(packet[DNS].an):
                                try:
                                    answer = packet[DNS].an[i]
                                    if hasattr(answer, 'rdata'):
                                        if isinstance(answer.rdata, bytes):
                                            answers.append(answer.rdata.decode('utf-8', errors='ignore'))
                                        else:
                                            answers.append(str(answer.rdata))
                                except:
                                    pass
                        dns_data['dns_answers'] = answers
                    
                    packet_data['dns'] = json.dumps(dns_data)
                
            elif ICMP in packet:
                packet_data['protocol_name'] = 'ICMP'
                packet_data['icmp_type'] = packet[ICMP].type
                packet_data['icmp_code'] = packet[ICMP].code
        
        # Handle ARP packets
        elif ARP in packet:
            packet_data['protocol_name'] = 'ARP'
            packet_data['src_ip'] = packet[ARP].psrc
            packet_data['dst_ip'] = packet[ARP].pdst
            packet_data['arp_op'] = packet[ARP].op
            packet_data['arp_op_name'] = 'REQUEST' if packet[ARP].op == 1 else 'REPLY'
        
        # Determine packet direction (simplified)
        if 'src_ip' in packet_data:
            # Check if source IP is private
            src_ip = packet_data['src_ip']
            is_private = (
                src_ip.startswith('10.') or 
                src_ip.startswith('172.16.') or 
                src_ip.startswith('172.17.') or 
                src_ip.startswith('172.18.') or 
                src_ip.startswith('172.19.') or 
                src_ip.startswith('172.2') or 
                src_ip.startswith('172.30.') or 
                src_ip.startswith('172.31.') or 
                src_ip.startswith('192.168.') or
                src_ip == '127.0.0.1'
            )
            packet_data['direction'] = 'outgoing' if is_private else 'incoming'
        
        # Calculate payload size
        if 'total_length' in packet_data and 'header_length' in packet_data:
            # IP header length + transport header length
            ip_header_len = packet_data.get('header_length', 20)  # Default IP header is 20 bytes
            transport_header_len = 0
            
            if TCP in packet:
                transport_header_len = packet[TCP].dataofs * 4
            elif UDP in packet:
                transport_header_len = 8
            
            packet_data['payload_size'] = packet_data['total_length'] - ip_header_len - transport_header_len
            
            # Ensure payload size is not negative
            if packet_data['payload_size'] < 0:
                packet_data['payload_size'] = 0
        else:
            # Fallback: calculate from Raw layer if available
            if Raw in packet:
                packet_data['payload_size'] = len(packet[Raw].load)
            else:
                packet_data['payload_size'] = 0
        
        # Store packet in database
        columns = []
        values = []
        placeholders = []
        
        for key, value in packet_data.items():
            if value is not None:
                columns.append(key)
                values.append(value)
                placeholders.append('%s')
        
        # Build SQL query
        sql = f"INSERT INTO packets ({', '.join(columns)}) VALUES ({', '.join(placeholders)})"
        
        # Execute query
        cursor.execute(sql, values)
        db_conn.commit()
        
        logger.info(f"Stored packet: {packet_data['protocol_name']} from {packet_data.get('src_ip', 'unknown')} to {packet_data.get('dst_ip', 'unknown')}")
        
    except Exception as e:
        logger.error(f"Error processing packet: {e}")
        db_conn.rollback()

def main():
    # Load configuration
    config = load_config()
    if not config:
        logger.error("Failed to load configuration")
        return 1
    
    # Get database configuration
    db_config = config.get('database', {})
    
    try:
        # Connect to database
        logger.info(f"Connecting to database at {db_config['host']}:{db_config['port']}")
        conn = psycopg2.connect(
            host=db_config['host'],
            port=db_config['port'],
            dbname=db_config['name'],
            user=db_config['user'],
            password=db_config['password']
        )
        cursor = conn.cursor()
        
        # Get available interfaces
        from scapy.arch import get_if_list
        interfaces = get_if_list()
        logger.info(f"Available interfaces: {interfaces}")
        
        # Use the first interface if none specified
        interface = config.get('interface')
        if not interface and interfaces:
            interface = interfaces[0]
            logger.info(f"Using interface: {interface}")
        
        if not interface:
            logger.error("No network interface available")
            return 1
        
        # Start packet capture
        logger.info(f"Starting packet capture on interface {interface}")
        logger.info("Press Ctrl+C to stop capture")
        
        # Capture packets
        packet_count = int(config.get('packet_count', 0))
        if packet_count > 0:
            logger.info(f"Will capture {packet_count} packets")
            sniff(
                iface=interface,
                prn=lambda pkt: process_packet(pkt, conn, cursor),
                store=0,
                count=packet_count
            )
        else:
            # Capture indefinitely
            sniff(
                iface=interface,
                prn=lambda pkt: process_packet(pkt, conn, cursor),
                store=0
            )
        
        # Close database connection
        cursor.close()
        conn.close()
        
        logger.info("Packet capture completed")
        return 0
    
    except KeyboardInterrupt:
        logger.info("Packet capture stopped by user")
        return 0
    
    except Exception as e:
        logger.error(f"Error: {e}")
        return 1

def export_to_csv(db_config, output_file='captured_packets.csv'):
    """
    Export captured packets from database to CSV format suitable for ML analysis
    """
    try:
        import pandas as pd
        
        # Connect to database
        conn = psycopg2.connect(
            host=db_config['host'],
            port=db_config['port'],
            dbname=db_config['name'],
            user=db_config['user'],
            password=db_config['password']
        )
        
        # Query to get all packet data
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
            direction,
            tcp_flags,
            tcp_seq,
            tcp_ack,
            http,
            dns,
            icmp_type,
            icmp_code,
            arp_op,
            mac_src,
            mac_dst
        FROM packets 
        ORDER BY timestamp_epoch
        """
        
        # Read data into DataFrame
        df = pd.read_sql_query(query, conn)
        
        # Export to CSV
        df.to_csv(output_file, index=False)
        logger.info(f"Exported {len(df)} packets to {output_file}")
        
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"Error exporting to CSV: {e}")
        return False

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='PyGuard Network Traffic Capture')
    parser.add_argument('--export-csv', action='store_true', help='Export captured data to CSV')
    parser.add_argument('--output-file', default='captured_packets.csv', help='Output CSV file name')
    
    args = parser.parse_args()
    
    if args.export_csv:
        # Load configuration and export to CSV
        config = load_config()
        if config:
            db_config = config.get('database', {})
            if export_to_csv(db_config, args.output_file):
                sys.exit(0)
            else:
                sys.exit(1)
        else:
            logger.error("Failed to load configuration")
            sys.exit(1)
    else:
        # Run normal packet capture
        sys.exit(main())