#!/usr/bin/env python3
"""
Complete PyGuard ML Workflow Demo
This script demonstrates the complete workflow from packet capture to ML-ready flow features.
It shows how to use all the components together for network traffic analysis.
"""

import os
import sys
import time
import logging
import argparse
import subprocess
from pathlib import Path
import pandas as pd

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def run_demo_workflow(demo_type='pcap', pcap_file=None, capture_duration=30, 
                     packet_count=1000, output_dir='./demo_output'):
    """
    Run complete demo workflow
    
    Args:
        demo_type: Type of demo ('pcap', 'live_capture', 'database')
        pcap_file: Path to PCAP file (for pcap demo)
        capture_duration: Duration for live capture
        packet_count: Number of packets to capture
        output_dir: Output directory for results
    """
    logger.info("=" * 60)
    logger.info("PyGuard Complete ML Workflow Demo")
    logger.info("=" * 60)
    
    # Create output directory
    Path(output_dir).mkdir(exist_ok=True)
    
    if demo_type == 'pcap' and pcap_file:
        return demo_pcap_to_flows(pcap_file, output_dir)
    elif demo_type == 'live_capture':
        return demo_live_capture_to_flows(capture_duration, packet_count, output_dir)
    elif demo_type == 'database':
        return demo_database_to_flows(output_dir)
    else:
        logger.error("Invalid demo type or missing PCAP file")
        return False

def demo_pcap_to_flows(pcap_file, output_dir):
    """
    Demo: Convert PCAP file to flow features
    """
    logger.info("Demo 1: PCAP File to Flow Features")
    logger.info("-" * 40)
    
    if not os.path.exists(pcap_file):
        logger.error(f"PCAP file not found: {pcap_file}")
        return False
    
    try:
        # Step 1: Convert PCAP to flow features
        logger.info("Step 1: Converting PCAP to flow features...")
        flow_output = os.path.join(output_dir, 'pcap_flows.csv')
        
        cmd = [
            sys.executable, 'pcap_to_flows.py',
            pcap_file,
            '-o', flow_output,
            '--verbose'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info("✓ PCAP to flows conversion completed successfully")
            
            # Step 2: Analyze the results
            logger.info("Step 2: Analyzing flow features...")
            analyze_flow_features(flow_output)
            
            logger.info(f"✓ Demo completed! Results saved in: {output_dir}")
            return True
        else:
            logger.error(f"✗ PCAP conversion failed: {result.stderr}")
            return False
            
    except Exception as e:
        logger.error(f"✗ Demo failed: {e}")
        return False

def demo_live_capture_to_flows(duration, packet_count, output_dir):
    """
    Demo: Live packet capture to flow features
    """
    logger.info("Demo 2: Live Capture to Flow Features")
    logger.info("-" * 40)
    
    try:
        # Step 1: Capture packets to CSV
        logger.info(f"Step 1: Capturing {packet_count} packets (or {duration}s timeout)...")
        packet_csv = os.path.join(output_dir, 'live_packets.csv')
        
        cmd = [
            sys.executable, 'capture_to_csv.py',
            '-o', packet_csv,
            '-c', str(packet_count),
            '-t', str(duration),
            '--verbose'
        ]
        
        logger.info("Starting live packet capture... (Press Ctrl+C to stop early)")
        result = subprocess.run(cmd)
        
        if result.returncode == 0 and os.path.exists(packet_csv):
            logger.info("✓ Live packet capture completed")
            
            # Step 2: Convert packets to flows using ML converter
            logger.info("Step 2: Converting packets to flow features...")
            flow_output = os.path.join(output_dir, 'live_flows.csv')
            
            cmd = [
                sys.executable, 'ml_flow_converter.py',
                '--source', 'csv',
                '--input-file', packet_csv,
                '--output-file', flow_output
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("✓ Flow conversion completed successfully")
                
                # Step 3: Analyze results
                logger.info("Step 3: Analyzing flow features...")
                analyze_flow_features(flow_output)
                
                logger.info(f"✓ Demo completed! Results saved in: {output_dir}")
                return True
            else:
                logger.error(f"✗ Flow conversion failed: {result.stderr}")
                return False
        else:
            logger.error("✗ Live capture failed or no packets captured")
            return False
            
    except KeyboardInterrupt:
        logger.info("Demo interrupted by user")
        return False
    except Exception as e:
        logger.error(f"✗ Demo failed: {e}")
        return False

def demo_database_to_flows(output_dir):
    """
    Demo: Database packets to flow features
    """
    logger.info("Demo 3: Database to Flow Features")
    logger.info("-" * 40)
    
    try:
        # Step 1: Check if database has data
        logger.info("Step 1: Checking database for existing packet data...")
        
        # Step 2: Convert database to flows
        logger.info("Step 2: Converting database packets to flow features...")
        flow_output = os.path.join(output_dir, 'database_flows.csv')
        
        cmd = [
            sys.executable, 'ml_flow_converter.py',
            '--source', 'database',
            '--output-file', flow_output,
            '--limit', '10000'  # Limit for demo
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info("✓ Database to flows conversion completed")
            
            # Step 3: Analyze results
            logger.info("Step 3: Analyzing flow features...")
            analyze_flow_features(flow_output)
            
            logger.info(f"✓ Demo completed! Results saved in: {output_dir}")
            return True
        else:
            logger.error(f"✗ Database conversion failed: {result.stderr}")
            logger.info("Note: Make sure you have packet data in your database")
            logger.info("You can capture packets first using: python capture_traffic.py")
            return False
            
    except Exception as e:
        logger.error(f"✗ Demo failed: {e}")
        return False

def analyze_flow_features(csv_file):
    """
    Analyze and display flow features statistics
    """
    try:
        if not os.path.exists(csv_file):
            logger.warning(f"Flow file not found: {csv_file}")
            return
        
        df = pd.read_csv(csv_file)
        
        if len(df) == 0:
            logger.warning("No flow data found")
            return
        
        logger.info(f"Flow Analysis Results:")
        logger.info(f"  📊 Total flows: {len(df)}")
        
        # Protocol distribution
        if 'Protocol' in df.columns:
            protocol_counts = df['Protocol'].value_counts()
            logger.info("  🌐 Protocol distribution:")
            for protocol, count in protocol_counts.items():
                protocol_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(protocol, f'Protocol-{protocol}')
                percentage = (count / len(df)) * 100
                logger.info(f"    {protocol_name}: {count} ({percentage:.1f}%)")
        
        # Flow duration statistics
        if 'Flow_Duration' in df.columns:
            avg_duration = df['Flow_Duration'].mean()
            max_duration = df['Flow_Duration'].max()
            logger.info(f"  ⏱️  Average flow duration: {avg_duration:.4f} seconds")
            logger.info(f"  ⏱️  Maximum flow duration: {max_duration:.4f} seconds")
        
        # Packet statistics
        if 'Tot_Fwd_Pkts' in df.columns and 'Tot_Bwd_Pkts' in df.columns:
            total_packets = df['Tot_Fwd_Pkts'].sum() + df['Tot_Bwd_Pkts'].sum()
            avg_packets_per_flow = total_packets / len(df)
            logger.info(f"  📦 Total packets: {total_packets}")
            logger.info(f"  📦 Average packets per flow: {avg_packets_per_flow:.2f}")
        
        # Byte statistics
        if 'TotLen_Fwd_Pkts' in df.columns and 'TotLen_Bwd_Pkts' in df.columns:
            total_bytes = df['TotLen_Fwd_Pkts'].sum() + df['TotLen_Bwd_Pkts'].sum()
            avg_bytes_per_flow = total_bytes / len(df)
            logger.info(f"  💾 Total bytes: {total_bytes:,}")
            logger.info(f"  💾 Average bytes per flow: {avg_bytes_per_flow:.2f}")
        
        # TCP flags statistics
        tcp_flag_cols = ['SYN_Flag_Cnt', 'ACK_Flag_Cnt', 'FIN_Flag_Cnt', 'RST_Flag_Cnt']
        tcp_flags_present = [col for col in tcp_flag_cols if col in df.columns]
        if tcp_flags_present:
            logger.info("  🚩 TCP Flags:")
            for col in tcp_flags_present:
                flag_name = col.replace('_Flag_Cnt', '')
                total_flags = df[col].sum()
                flows_with_flag = (df[col] > 0).sum()
                logger.info(f"    {flag_name}: {total_flags} total, {flows_with_flag} flows")
        
        # Top source/destination IPs
        if 'Src_IP' in df.columns:
            top_src_ips = df['Src_IP'].value_counts().head(5)
            logger.info("  🔝 Top 5 source IPs:")
            for ip, count in top_src_ips.items():
                logger.info(f"    {ip}: {count} flows")
        
        # Feature completeness check
        essential_features = [
            'Flow_Duration', 'Tot_Fwd_Pkts', 'Tot_Bwd_Pkts',
            'Flow_IAT_Mean', 'Fwd_Pkt_Len_Mean', 'Bwd_Pkt_Len_Mean'
        ]
        missing_features = [f for f in essential_features if f not in df.columns]
        
        if missing_features:
            logger.warning(f"  ⚠️  Missing essential features: {missing_features}")
        else:
            logger.info("  ✅ All essential features present")
        
        logger.info(f"  📁 Flow features saved to: {csv_file}")
        logger.info("  🤖 Ready for machine learning analysis!")
        
    except Exception as e:
        logger.error(f"Error analyzing flow features: {e}")

def print_usage_examples():
    """
    Print usage examples
    """
    print("\n" + "="*60)
    print("PyGuard ML Workflow - Usage Examples")
    print("="*60)
    
    print("\n1. Convert existing PCAP file to flow features:")
    print("   python demo_complete_workflow.py pcap --pcap-file traffic.pcap")
    
    print("\n2. Live capture and convert to flows:")
    print("   python demo_complete_workflow.py live --duration 60 --count 5000")
    
    print("\n3. Convert database packets to flows:")
    print("   python demo_complete_workflow.py database")
    
    print("\n4. Direct PCAP to flows conversion:")
    print("   python pcap_to_flows.py input.pcap -o flows.csv")
    
    print("\n5. Live capture to CSV:")
    print("   python capture_to_csv.py -o packets.csv -c 1000")
    
    print("\n6. Convert CSV packets to flows:")
    print("   python ml_flow_converter.py --source csv --input-file packets.csv")
    
    print("\nOutput files will contain CIC-IDS compatible features for ML analysis!")
    print("="*60)

def main():
    """
    Main function
    """
    parser = argparse.ArgumentParser(
        description='PyGuard Complete ML Workflow Demo',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='demo_type', help='Demo type')
    
    # PCAP demo
    pcap_parser = subparsers.add_parser('pcap', help='Convert PCAP file to flows')
    pcap_parser.add_argument('--pcap-file', required=True, help='Input PCAP file')
    pcap_parser.add_argument('--output-dir', default='./demo_output', help='Output directory')
    
    # Live capture demo
    live_parser = subparsers.add_parser('live', help='Live capture to flows')
    live_parser.add_argument('--duration', type=int, default=30, help='Capture duration (seconds)')
    live_parser.add_argument('--count', type=int, default=1000, help='Packet count')
    live_parser.add_argument('--output-dir', default='./demo_output', help='Output directory')
    
    # Database demo
    db_parser = subparsers.add_parser('database', help='Database packets to flows')
    db_parser.add_argument('--output-dir', default='./demo_output', help='Output directory')
    
    # Examples
    examples_parser = subparsers.add_parser('examples', help='Show usage examples')
    
    args = parser.parse_args()
    
    if args.demo_type == 'examples':
        print_usage_examples()
        return 0
    
    if not args.demo_type:
        parser.print_help()
        print_usage_examples()
        return 1
    
    try:
        if args.demo_type == 'pcap':
            success = run_demo_workflow(
                demo_type='pcap',
                pcap_file=args.pcap_file,
                output_dir=args.output_dir
            )
        elif args.demo_type == 'live':
            success = run_demo_workflow(
                demo_type='live_capture',
                capture_duration=args.duration,
                packet_count=args.count,
                output_dir=args.output_dir
            )
        elif args.demo_type == 'database':
            success = run_demo_workflow(
                demo_type='database',
                output_dir=args.output_dir
            )
        
        if success:
            logger.info("\n🎉 Demo completed successfully!")
            logger.info("Your network traffic data is now ready for ML analysis!")
            return 0
        else:
            logger.error("\n❌ Demo failed!")
            return 1
            
    except KeyboardInterrupt:
        logger.info("\nDemo interrupted by user")
        return 0
    except Exception as e:
        logger.error(f"\nDemo failed with error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())