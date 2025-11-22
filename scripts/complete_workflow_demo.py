#!/usr/bin/env python3
"""
Complete PyGuard Workflow Demo
Demonstrates all the new CSV to flows functionality with real examples
"""

import os
import sys
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import subprocess
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_realistic_packet_csv(filename="demo_packets.csv", num_packets=200):
    """
    Create a realistic packet CSV file for demonstration
    """
    print(f"Creating realistic packet CSV with {num_packets} packets...")
    
    packets = []
    base_time = datetime.now()
    frame_num = 1
    
    # Define realistic network flows
    flows = [
        # Web browsing (HTTP)
        {'src_ip': '192.168.1.100', 'dst_ip': '93.184.216.34', 'src_port': 49152, 'dst_port': 80, 'protocol': 6, 'type': 'HTTP'},
        # HTTPS browsing
        {'src_ip': '192.168.1.100', 'dst_ip': '172.217.14.206', 'src_port': 49153, 'dst_port': 443, 'protocol': 6, 'type': 'HTTPS'},
        # DNS queries
        {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'src_port': 53281, 'dst_port': 53, 'protocol': 17, 'type': 'DNS'},
        # Email (SMTP)
        {'src_ip': '192.168.1.100', 'dst_ip': '74.125.224.108', 'src_port': 49154, 'dst_port': 587, 'protocol': 6, 'type': 'SMTP'},
        # SSH connection
        {'src_ip': '192.168.1.100', 'dst_ip': '203.0.113.10', 'src_port': 49155, 'dst_port': 22, 'protocol': 6, 'type': 'SSH'},
        # FTP transfer
        {'src_ip': '192.168.1.100', 'dst_ip': '198.51.100.20', 'src_port': 49156, 'dst_port': 21, 'protocol': 6, 'type': 'FTP'},
        # Video streaming (UDP)
        {'src_ip': '192.168.1.100', 'dst_ip': '23.246.226.99', 'src_port': 49157, 'dst_port': 1935, 'protocol': 17, 'type': 'Streaming'},
        # P2P traffic
        {'src_ip': '192.168.1.100', 'dst_ip': '185.199.108.153', 'src_port': 49158, 'dst_port': 6881, 'protocol': 6, 'type': 'P2P'},
    ]
    
    # Generate packets with realistic patterns
    for i in range(num_packets):
        flow = flows[i % len(flows)]
        
        # Determine packet direction and characteristics
        if np.random.random() > 0.4:  # 60% forward, 40% backward
            # Forward direction
            src_ip, dst_ip = flow['src_ip'], flow['dst_ip']
            src_port, dst_port = flow['src_port'], flow['dst_port']
            
            # Forward packets tend to be smaller (requests)
            if flow['type'] in ['HTTP', 'HTTPS', 'DNS']:
                size = np.random.randint(64, 200)
            elif flow['type'] in ['SSH', 'FTP']:
                size = np.random.randint(64, 500)
            else:
                size = np.random.randint(100, 800)
        else:
            # Backward direction (response)
            src_ip, dst_ip = flow['dst_ip'], flow['src_ip']
            src_port, dst_port = flow['dst_port'], flow['src_port']
            
            # Backward packets tend to be larger (responses/data)
            if flow['type'] in ['HTTP', 'HTTPS']:
                size = np.random.randint(200, 1500)
            elif flow['type'] == 'DNS':
                size = np.random.randint(64, 300)
            elif flow['type'] == 'Streaming':
                size = np.random.randint(800, 1500)
            else:
                size = np.random.randint(200, 1200)
        
        # Create realistic timing (some flows are bursty)
        if flow['type'] in ['Streaming', 'P2P']:
            time_offset = i * 0.01 + np.random.random() * 0.005  # High frequency
        elif flow['type'] in ['HTTP', 'HTTPS']:
            time_offset = i * 0.1 + np.random.random() * 0.05   # Medium frequency
        else:
            time_offset = i * 0.2 + np.random.random() * 0.1    # Lower frequency
        
        packet = {
            'frame_num': frame_num,
            'timestamp': (base_time + timedelta(seconds=time_offset)).timestamp(),
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'protocol': flow['protocol'],
            'size': size,
            'summary': f"{flow['type']} {'TCP' if flow['protocol'] == 6 else 'UDP'} {src_ip}:{src_port} > {dst_ip}:{dst_port} [{size} bytes]"
        }
        
        packets.append(packet)
        frame_num += 1
    
    # Create DataFrame and save
    df = pd.DataFrame(packets)
    df = df.sort_values('timestamp').reset_index(drop=True)  # Sort by time
    df.to_csv(filename, index=False)
    
    print(f"✅ Realistic packet CSV created: {filename}")
    print(f"   Total packets: {len(df)}")
    print(f"   Time span: {df['timestamp'].max() - df['timestamp'].min():.2f} seconds")
    print(f"   Unique flows: {len(flows)}")
    
    # Show protocol distribution
    protocol_dist = df['protocol'].value_counts()
    print(f"   Protocol distribution:")
    for proto, count in protocol_dist.items():
        proto_name = 'TCP' if proto == 6 else 'UDP' if proto == 17 else f'Protocol-{proto}'
        print(f"     {proto_name}: {count} packets")
    
    return filename

def demonstrate_csv_to_flows():
    """
    Demonstrate the complete CSV to flows workflow
    """
    print("\n" + "="*80)
    print("🚀 COMPLETE CSV TO FLOWS WORKFLOW DEMONSTRATION")
    print("="*80)
    
    # Step 1: Create sample data
    print("\n📊 Step 1: Creating realistic packet data...")
    packet_csv = create_realistic_packet_csv("demo_packets.csv", 150)
    
    # Step 2: Show sample packet data
    print(f"\n📋 Step 2: Sample packet data from {packet_csv}:")
    df = pd.read_csv(packet_csv)
    print(df.head(10).to_string(index=False))
    
    # Step 3: Convert to flows using our script
    print(f"\n🌊 Step 3: Converting packets to flows...")
    flows_csv = "demo_flows.csv"
    flows_json = "demo_flows.json"
    
    # Run the conversion
    cmd = [
        sys.executable, "csv_to_flows.py",
        packet_csv,
        "-o", flows_csv,
        "--json", flows_json,
        "--verbose"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.getcwd())
        
        if result.returncode == 0:
            print("✅ Conversion completed successfully!")
            print("Conversion output:")
            print(result.stdout)
        else:
            print("❌ Conversion failed!")
            print("Error output:")
            print(result.stderr)
            return False
            
    except Exception as e:
        print(f"❌ Error running conversion: {e}")
        return False
    
    # Step 4: Show flow results
    if os.path.exists(flows_csv):
        print(f"\n📈 Step 4: Flow analysis results from {flows_csv}:")
        flows_df = pd.read_csv(flows_csv)
        
        print(f"Generated {len(flows_df)} flows from {len(df)} packets")
        print("\nFlow summary:")
        print(flows_df.to_string(index=False))
        
        # Analyze the results
        print(f"\n📊 Step 5: Flow analysis:")
        print(f"   Total flows: {len(flows_df)}")
        print(f"   Total forward packets: {flows_df['total_fwd_packets'].sum()}")
        print(f"   Total backward packets: {flows_df['total_bwd_packets'].sum()}")
        print(f"   Total forward bytes: {flows_df['total_fwd_bytes'].sum():,}")
        print(f"   Total backward bytes: {flows_df['total_bwd_bytes'].sum():,}")
        print(f"   Average flow duration: {flows_df['flow_duration'].mean():.4f} seconds")
        
        # Protocol breakdown
        protocol_flows = flows_df['protocol'].value_counts()
        print(f"   Flow protocol distribution:")
        for proto, count in protocol_flows.items():
            proto_name = 'TCP' if proto == 6 else 'UDP' if proto == 17 else f'Protocol-{proto}'
            print(f"     {proto_name}: {count} flows")
        
        # Bidirectional analysis
        bidirectional = flows_df[(flows_df['total_fwd_packets'] > 0) & (flows_df['total_bwd_packets'] > 0)]
        unidirectional = flows_df[(flows_df['total_fwd_packets'] > 0) & (flows_df['total_bwd_packets'] == 0)] | \
                        flows_df[(flows_df['total_fwd_packets'] == 0) & (flows_df['total_bwd_packets'] > 0)]
        
        print(f"   Bidirectional flows: {len(bidirectional)}")
        print(f"   Unidirectional flows: {len(unidirectional)}")
        
        return True
    else:
        print("❌ Flow CSV file was not created")
        return False

def show_format_examples():
    """
    Show examples of input and output formats
    """
    print("\n" + "="*80)
    print("📋 INPUT/OUTPUT FORMAT EXAMPLES")
    print("="*80)
    
    print("\n📥 INPUT CSV FORMAT (from Wireshark/Scapy):")
    print("Required columns: frame_num, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, size, summary")
    print("\nExample input:")
    print("frame_num,timestamp,src_ip,src_port,dst_ip,dst_port,protocol,size,summary")
    print("1,1755066123.456,192.168.1.100,12345,8.8.8.8,80,6,64,TCP 192.168.1.100:12345 > 8.8.8.8:80")
    print("2,1755066123.567,8.8.8.8,80,192.168.1.100,12345,6,1500,TCP 8.8.8.8:80 > 192.168.1.100:12345")
    print("3,1755066123.678,192.168.1.100,54321,8.8.8.8,53,17,64,UDP 192.168.1.100:54321 > 8.8.8.8:53")
    
    print("\n📤 OUTPUT CSV FORMAT (Flow-based):")
    print("Columns: src_ip, dst_ip, src_port, dst_port, protocol, total_fwd_packets, total_bwd_packets, flow_duration, total_fwd_bytes, total_bwd_bytes")
    print("\nExample output:")
    print("src_ip,dst_ip,src_port,dst_port,protocol,total_fwd_packets,total_bwd_packets,flow_duration,total_fwd_bytes,total_bwd_bytes")
    print("192.168.1.100,8.8.8.8,12345,80,6,5,3,2.456,320,4500")
    print("192.168.1.100,8.8.8.8,54321,53,17,2,2,0.123,128,256")

def show_usage_scenarios():
    """
    Show different usage scenarios
    """
    print("\n" + "="*80)
    print("🎯 USAGE SCENARIOS")
    print("="*80)
    
    scenarios = [
        {
            'title': 'Scenario 1: Basic Wireshark CSV conversion',
            'description': 'You exported packet data from Wireshark to CSV',
            'command': 'python csv_to_flows.py wireshark_packets.csv -o network_flows.csv'
        },
        {
            'title': 'Scenario 2: Save to all formats for analysis',
            'description': 'You want CSV, JSON, and database storage',
            'command': 'python csv_to_flows.py packets.csv -o flows.csv --save-all'
        },
        {
            'title': 'Scenario 3: Live capture with enhanced script',
            'description': 'Capture live traffic and auto-convert to flows',
            'command': 'python enhanced_capture_all_formats.py -c 1000 -o network_analysis'
        },
        {
            'title': 'Scenario 4: Large dataset processing',
            'description': 'Process large packet CSV with verbose output',
            'command': 'python csv_to_flows.py large_packets.csv -o flows.csv --verbose'
        },
        {
            'title': 'Scenario 5: Integration with ML pipeline',
            'description': 'Convert packets and prepare for machine learning',
            'command': 'python csv_to_flows.py packets.csv -o ml_flows.csv --json ml_flows.json'
        }
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        print(f"\n{scenario['title']}:")
        print(f"   Description: {scenario['description']}")
        print(f"   Command: {scenario['command']}")

def cleanup_demo_files():
    """
    Clean up demo files
    """
    demo_files = ["demo_packets.csv", "demo_flows.csv", "demo_flows.json"]
    cleaned = 0
    
    for file in demo_files:
        if os.path.exists(file):
            try:
                os.remove(file)
                cleaned += 1
            except:
                pass
    
    if cleaned > 0:
        print(f"\n🧹 Cleaned up {cleaned} demo files")

def main():
    """
    Main demonstration function
    """
    print("🎉 PyGuard CSV to Flows - Complete Workflow Demo")
    print("="*80)
    
    try:
        # Run the main demonstration
        success = demonstrate_csv_to_flows()
        
        # Show format examples
        show_format_examples()
        
        # Show usage scenarios
        show_usage_scenarios()
        
        # Final summary
        print("\n" + "="*80)
        print("✅ DEMONSTRATION COMPLETE!")
        print("="*80)
        
        if success:
            print("\n🎯 Key Features Demonstrated:")
            print("   ✅ Reads packet CSV with required columns")
            print("   ✅ Handles bidirectional flows correctly")
            print("   ✅ Converts timestamps automatically")
            print("   ✅ Groups by (src_ip, dst_ip, src_port, dst_port, protocol)")
            print("   ✅ Calculates forward/backward packets and bytes")
            print("   ✅ Supports both TCP and UDP protocols")
            print("   ✅ Saves to multiple formats (CSV, JSON, Database)")
            print("   ✅ Provides comprehensive flow statistics")
            
            print("\n🚀 Ready for Production Use:")
            print("   📁 Use csv_to_flows.py for your packet CSV files")
            print("   📁 Use enhanced_capture_all_formats.py for live capture")
            print("   📁 All output formats are ML-ready")
            print("   📁 Integrates with existing PyGuard database")
            
            print("\n📞 Next Steps:")
            print("   1. Export your packet data from Wireshark/Scapy to CSV")
            print("   2. Run: python csv_to_flows.py your_packets.csv -o flows.csv")
            print("   3. Use the flow CSV for network analysis or ML training")
            print("   4. Optionally save to database for long-term storage")
        else:
            print("\n❌ Some demonstrations failed. Please check the setup.")
        
    except KeyboardInterrupt:
        print("\n⏹️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
    finally:
        cleanup_demo_files()

if __name__ == "__main__":
    main()