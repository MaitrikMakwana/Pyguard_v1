#!/usr/bin/env python3
"""
Enhanced PyGuard Packet Capture with Multi-Format Output
Captures network packets and automatically saves to CSV, JSON, and Database formats.
Also converts packet-level data to flow-based statistics in all formats.
"""

import os
import sys
import time
import logging
import yaml
import pandas as pd
import json
import psycopg2
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, DNS, ARP, Raw
from pathlib import Path
import argparse
from csv_to_flows import CSVToFlowConverter

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class EnhancedMultiFormatCapture:
    """
    Enhanced packet capture that saves to multiple formats and generates flow statistics
    """
    
    def __init__(self, config_path='config.yaml', output_dir='./output'):
        self.config = self.load_config(config_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.captured_packets = []
        self.packet_count = 0
        self.db_connection = None
        self.db_cursor = None
        
        # Initialize database connection if enabled
        self.init_database()
    
    def load_config(self, config_path):
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return {}
    
    def init_database(self):
        """Initialize database connection"""
        if not self.config.get('database', {}).get('enabled', False):
            logger.info("Database storage is disabled")
            return
        
        try:
            db_config = self.config['database']
            self.db_connection = psycopg2.connect(
                host=db_config['host'],
                port=db_config['port'],
                dbname=db_config['name'],
                user=db_config['user'],
                password=db_config['password']
            )
            self.db_cursor = self.db_connection.cursor()
            logger.info("Database connection established")
            
            # Create tables if they don't exist
            self.create_database_tables()
            
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            self.db_connection = None
            self.db_cursor = None
    
    def create_database_tables(self):
        """Create database tables for packets and flows"""
        try:
            # Create packets table (if not exists)
            create_packets_table = """
            CREATE TABLE IF NOT EXISTS packets (
                id SERIAL PRIMARY KEY,
                frame_num INTEGER,
                timestamp TIMESTAMP,
                timestamp_epoch DOUBLE PRECISION,
                src_ip INET,
                dst_ip INET,
                src_port INTEGER,
                dst_port INTEGER,
                protocol INTEGER,
                protocol_name VARCHAR(20),
                size INTEGER,
                total_length INTEGER,
                header_length INTEGER,
                payload_size INTEGER,
                summary TEXT,
                direction VARCHAR(20),
                flow_key VARCHAR(100),
                
                -- TCP specific fields
                tcp_seq BIGINT,
                tcp_ack BIGINT,
                window_size INTEGER,
                fin_flag INTEGER DEFAULT 0,
                syn_flag INTEGER DEFAULT 0,
                rst_flag INTEGER DEFAULT 0,
                psh_flag INTEGER DEFAULT 0,
                ack_flag INTEGER DEFAULT 0,
                urg_flag INTEGER DEFAULT 0,
                ece_flag INTEGER DEFAULT 0,
                cwr_flag INTEGER DEFAULT 0,
                
                -- Additional fields
                ttl INTEGER,
                ip_version INTEGER,
                is_fragmented BOOLEAN DEFAULT FALSE,
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
            
            # Create flows table (if not exists)
            create_flows_table = """
            CREATE TABLE IF NOT EXISTS flows (
                id SERIAL PRIMARY KEY,
                flow_key VARCHAR(100) UNIQUE,
                src_ip INET,
                dst_ip INET,
                src_port INTEGER,
                dst_port INTEGER,
                protocol INTEGER,
                protocol_name VARCHAR(20),
                
                -- Flow statistics
                total_fwd_packets INTEGER DEFAULT 0,
                total_bwd_packets INTEGER DEFAULT 0,
                total_packets INTEGER DEFAULT 0,
                flow_duration DOUBLE PRECISION DEFAULT 0,
                total_fwd_bytes BIGINT DEFAULT 0,
                total_bwd_bytes BIGINT DEFAULT 0,
                total_bytes BIGINT DEFAULT 0,
                
                -- Timing
                first_timestamp TIMESTAMP,
                last_timestamp TIMESTAMP,
                first_timestamp_epoch DOUBLE PRECISION,
                last_timestamp_epoch DOUBLE PRECISION,
                
                -- Additional flow features
                avg_packet_size DOUBLE PRECISION DEFAULT 0,
                max_packet_size INTEGER DEFAULT 0,
                min_packet_size INTEGER DEFAULT 0,
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
            
            self.db_cursor.execute(create_packets_table)
            self.db_cursor.execute(create_flows_table)
            self.db_connection.commit()
            logger.info("Database tables created/verified")
            
        except Exception as e:
            logger.error(f"Error creating database tables: {e}")
    
    def extract_packet_info(self, packet):
        """Extract comprehensive packet information"""
        packet_info = {
            'frame_num': self.packet_count,
            'timestamp': None,
            'timestamp_epoch': None,
            'src_ip': None,
            'dst_ip': None,
            'src_port': 0,
            'dst_port': 0,
            'protocol': 0,
            'protocol_name': 'UNKNOWN',
            'size': len(packet),
            'total_length': len(packet),
            'header_length': 0,
            'payload_size': 0,
            'summary': packet.summary(),
            'direction': 'unknown',
            'flow_key': '',
            
            # TCP specific
            'tcp_seq': 0,
            'tcp_ack': 0,
            'window_size': 0,
            'fin_flag': 0,
            'syn_flag': 0,
            'rst_flag': 0,
            'psh_flag': 0,
            'ack_flag': 0,
            'urg_flag': 0,
            'ece_flag': 0,
            'cwr_flag': 0,
            
            # Additional
            'ttl': 0,
            'ip_version': 0,
            'is_fragmented': False
        }
        
        try:
            # Extract timing
            if hasattr(packet, 'time') and packet.time:
                packet_info['timestamp_epoch'] = packet.time
                packet_info['timestamp'] = datetime.fromtimestamp(packet.time).isoformat()
            else:
                packet_info['timestamp_epoch'] = time.time()
                packet_info['timestamp'] = datetime.now().isoformat()
            
            # Extract IP information
            if IP in packet:
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst
                packet_info['protocol'] = packet[IP].proto
                packet_info['ip_version'] = packet[IP].version
                packet_info['total_length'] = packet[IP].len
                packet_info['ttl'] = packet[IP].ttl
                packet_info['header_length'] = packet[IP].ihl * 4
                packet_info['is_fragmented'] = packet[IP].frag > 0
                
                # Extract transport layer
                if TCP in packet:
                    packet_info['protocol_name'] = 'TCP'
                    packet_info['src_port'] = packet[TCP].sport
                    packet_info['dst_port'] = packet[TCP].dport
                    packet_info['header_length'] += packet[TCP].dataofs * 4
                    packet_info['tcp_seq'] = packet[TCP].seq
                    packet_info['tcp_ack'] = packet[TCP].ack
                    packet_info['window_size'] = packet[TCP].window
                    
                    # TCP flags
                    packet_info['fin_flag'] = int(packet[TCP].flags.F)
                    packet_info['syn_flag'] = int(packet[TCP].flags.S)
                    packet_info['rst_flag'] = int(packet[TCP].flags.R)
                    packet_info['psh_flag'] = int(packet[TCP].flags.P)
                    packet_info['ack_flag'] = int(packet[TCP].flags.A)
                    packet_info['urg_flag'] = int(packet[TCP].flags.U)
                    packet_info['ece_flag'] = int(packet[TCP].flags.E)
                    packet_info['cwr_flag'] = int(packet[TCP].flags.C)
                    
                elif UDP in packet:
                    packet_info['protocol_name'] = 'UDP'
                    packet_info['src_port'] = packet[UDP].sport
                    packet_info['dst_port'] = packet[UDP].dport
                    packet_info['header_length'] += 8
                    
                elif ICMP in packet:
                    packet_info['protocol_name'] = 'ICMP'
                    packet_info['header_length'] += 8
                
                # Calculate payload size
                packet_info['payload_size'] = packet_info['total_length'] - packet_info['header_length']
                if packet_info['payload_size'] < 0:
                    packet_info['payload_size'] = 0
                
                # Create flow key
                if packet_info['src_ip'] and packet_info['dst_ip']:
                    flow_key_parts = [
                        packet_info['src_ip'], packet_info['dst_ip'],
                        str(packet_info['src_port']), str(packet_info['dst_port']),
                        str(packet_info['protocol'])
                    ]
                    packet_info['flow_key'] = ':'.join(flow_key_parts)
                
                # Determine direction
                packet_info['direction'] = self.determine_direction(packet_info['src_ip'])
            
            elif ARP in packet:
                packet_info['protocol_name'] = 'ARP'
                packet_info['src_ip'] = packet[ARP].psrc
                packet_info['dst_ip'] = packet[ARP].pdst
                packet_info['flow_key'] = f"{packet_info['src_ip']}:{packet_info['dst_ip']}:ARP"
            
            return packet_info
            
        except Exception as e:
            logger.warning(f"Error extracting packet info: {e}")
            return packet_info
    
    def determine_direction(self, src_ip):
        """Determine packet direction"""
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
        """Handle captured packets"""
        self.packet_count += 1
        
        # Extract packet information
        packet_info = self.extract_packet_info(packet)
        self.captured_packets.append(packet_info)
        
        # Save to database immediately if enabled
        if self.db_connection:
            self.save_packet_to_database(packet_info)
        
        # Log progress
        if self.packet_count % 1000 == 0:
            logger.info(f"Captured {self.packet_count} packets...")
    
    def save_packet_to_database(self, packet_info):
        """Save individual packet to database"""
        try:
            # Prepare SQL query
            columns = []
            values = []
            placeholders = []
            
            for key, value in packet_info.items():
                if value is not None and key != 'timestamp':  # Skip timestamp string
                    columns.append(key)
                    values.append(value)
                    placeholders.append('%s')
            
            # Add timestamp as proper timestamp
            if packet_info['timestamp_epoch']:
                columns.append('timestamp')
                values.append(datetime.fromtimestamp(packet_info['timestamp_epoch']))
                placeholders.append('%s')
            
            sql = f"INSERT INTO packets ({', '.join(columns)}) VALUES ({', '.join(placeholders)})"
            self.db_cursor.execute(sql, values)
            
            # Commit every 100 packets for performance
            if self.packet_count % 100 == 0:
                self.db_connection.commit()
                
        except Exception as e:
            logger.warning(f"Error saving packet to database: {e}")
            if self.db_connection:
                self.db_connection.rollback()
    
    def capture_packets(self, interface=None, count=0, timeout=None, filter_expr=""):
        """Capture packets from network interface"""
        logger.info("Starting enhanced packet capture...")
        
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
                store=0
            )
            
            # Final database commit
            if self.db_connection:
                self.db_connection.commit()
            
            logger.info(f"Capture completed. Processed {self.packet_count} packets")
            
        except KeyboardInterrupt:
            logger.info("Capture interrupted by user")
            if self.db_connection:
                self.db_connection.commit()
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
            raise
    
    def save_all_formats(self, base_filename="captured_data"):
        """Save captured data to all formats (CSV, JSON, Database) and generate flows"""
        if not self.captured_packets:
            logger.warning("No packets to save")
            return False
        
        success = True
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        try:
            # 1. Save packets to CSV
            packets_csv = self.output_dir / f"{base_filename}_packets_{timestamp}.csv"
            packets_df = pd.DataFrame(self.captured_packets)
            packets_df.to_csv(packets_csv, index=False)
            logger.info(f"✅ Saved packets to CSV: {packets_csv}")
            
            # 2. Save packets to JSON
            packets_json = self.output_dir / f"{base_filename}_packets_{timestamp}.json"
            with open(packets_json, 'w') as f:
                json.dump(self.captured_packets, f, indent=2, default=str)
            logger.info(f"✅ Saved packets to JSON: {packets_json}")
            
            # 3. Convert to flows and save in all formats
            logger.info("Converting packets to flows...")
            converter = CSVToFlowConverter()
            flows_df = converter.convert_to_flows(packets_df)
            
            if flows_df is not None and len(flows_df) > 0:
                # Save flows to CSV
                flows_csv = self.output_dir / f"{base_filename}_flows_{timestamp}.csv"
                converter.save_to_csv(flows_df, flows_csv)
                logger.info(f"✅ Saved flows to CSV: {flows_csv}")
                
                # Save flows to JSON
                flows_json = self.output_dir / f"{base_filename}_flows_{timestamp}.json"
                converter.save_to_json(flows_df, flows_json)
                logger.info(f"✅ Saved flows to JSON: {flows_json}")
                
                # Save flows to database
                if self.db_connection:
                    self.save_flows_to_database(flows_df)
                    logger.info(f"✅ Saved flows to database")
                
                # Print flow summary
                converter.print_flow_summary(flows_df)
            else:
                logger.warning("No flows generated from packets")
            
            # 4. Database is already saved during capture
            if self.db_connection:
                logger.info(f"✅ Packets already saved to database during capture")
            
            logger.info("\n" + "="*60)
            logger.info("📁 ALL FILES SAVED SUCCESSFULLY:")
            logger.info(f"   📊 Packets CSV: {packets_csv}")
            logger.info(f"   📊 Packets JSON: {packets_json}")
            logger.info(f"   🌊 Flows CSV: {flows_csv}")
            logger.info(f"   🌊 Flows JSON: {flows_json}")
            if self.db_connection:
                logger.info(f"   🗄️  Database: packets and flows tables")
            logger.info("="*60)
            
            return True
            
        except Exception as e:
            logger.error(f"Error saving to all formats: {e}")
            return False
    
    def save_flows_to_database(self, flows_df):
        """Save flows to database"""
        try:
            for _, flow in flows_df.iterrows():
                # Check if flow already exists
                self.db_cursor.execute(
                    "SELECT id FROM flows WHERE flow_key = %s",
                    (flow['flow_key'],)
                )
                
                if self.db_cursor.fetchone():
                    # Update existing flow
                    update_sql = """
                    UPDATE flows SET
                        total_fwd_packets = %s,
                        total_bwd_packets = %s,
                        total_packets = %s,
                        flow_duration = %s,
                        total_fwd_bytes = %s,
                        total_bwd_bytes = %s,
                        total_bytes = %s,
                        last_timestamp = %s,
                        last_timestamp_epoch = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE flow_key = %s
                    """
                    self.db_cursor.execute(update_sql, (
                        flow['total_fwd_packets'],
                        flow['total_bwd_packets'],
                        flow['total_packets'],
                        flow['flow_duration'],
                        flow['total_fwd_bytes'],
                        flow['total_bwd_bytes'],
                        flow['total_bytes'],
                        datetime.fromtimestamp(flow['last_timestamp']),
                        flow['last_timestamp'],
                        flow['flow_key']
                    ))
                else:
                    # Insert new flow
                    insert_sql = """
                    INSERT INTO flows (
                        flow_key, src_ip, dst_ip, src_port, dst_port, protocol,
                        total_fwd_packets, total_bwd_packets, total_packets,
                        flow_duration, total_fwd_bytes, total_bwd_bytes, total_bytes,
                        first_timestamp, last_timestamp, first_timestamp_epoch, last_timestamp_epoch
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """
                    self.db_cursor.execute(insert_sql, (
                        flow['flow_key'],
                        flow['src_ip'],
                        flow['dst_ip'],
                        flow['src_port'],
                        flow['dst_port'],
                        flow['protocol'],
                        flow['total_fwd_packets'],
                        flow['total_bwd_packets'],
                        flow['total_packets'],
                        flow['flow_duration'],
                        flow['total_fwd_bytes'],
                        flow['total_bwd_bytes'],
                        flow['total_bytes'],
                        datetime.fromtimestamp(flow['first_timestamp']),
                        datetime.fromtimestamp(flow['last_timestamp']),
                        flow['first_timestamp'],
                        flow['last_timestamp']
                    ))
            
            self.db_connection.commit()
            
        except Exception as e:
            logger.error(f"Error saving flows to database: {e}")
            if self.db_connection:
                self.db_connection.rollback()
    
    def cleanup(self):
        """Cleanup database connections"""
        if self.db_cursor:
            self.db_cursor.close()
        if self.db_connection:
            self.db_connection.close()

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Enhanced PyGuard capture with multi-format output',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script captures network packets and automatically saves them in multiple formats:
1. Packet-level data: CSV, JSON, Database
2. Flow-level data: CSV, JSON, Database

Examples:
  python enhanced_capture_all_formats.py -c 1000 -o network_data
  python enhanced_capture_all_formats.py -t 60 --interface eth0
  python enhanced_capture_all_formats.py -c 5000 --filter "tcp port 80"
        """
    )
    
    parser.add_argument('-c', '--count', type=int, default=1000,
                       help='Number of packets to capture (default: 1000)')
    parser.add_argument('-t', '--timeout', type=int,
                       help='Capture timeout in seconds')
    parser.add_argument('-i', '--interface',
                       help='Network interface to capture from')
    parser.add_argument('-f', '--filter', default='',
                       help='BPF filter expression')
    parser.add_argument('-o', '--output', default='captured_data',
                       help='Base filename for output files')
    parser.add_argument('--output-dir', default='./output',
                       help='Output directory (default: ./output)')
    parser.add_argument('--config', default='config.yaml',
                       help='Configuration file path')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Create enhanced capture instance
        capturer = EnhancedMultiFormatCapture(args.config, args.output_dir)
        
        # Start capture
        capturer.capture_packets(
            interface=args.interface,
            count=args.count,
            timeout=args.timeout,
            filter_expr=args.filter
        )
        
        # Save to all formats
        success = capturer.save_all_formats(args.output)
        
        # Cleanup
        capturer.cleanup()
        
        if success:
            logger.info("🎉 Enhanced capture completed successfully!")
            logger.info("All data saved in multiple formats and ready for analysis!")
            return 0
        else:
            logger.error("❌ Some operations failed")
            return 1
            
    except KeyboardInterrupt:
        logger.info("Capture interrupted by user")
        return 0
    except Exception as e:
        logger.error(f"❌ Capture failed: {e}")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())