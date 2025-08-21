#!/usr/bin/env python3
"""
Test script for CSV to flows conversion
Creates sample packet data and demonstrates the conversion process
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import os
from csv_to_flows import CSVToFlowConverter

def create_sample_packet_csv(filename="sample_packets.csv", num_packets=100):
    """
    Create a sample packet CSV file for testing
    """
    print(f"Creating sample packet CSV with {num_packets} packets...")
    
    # Sample data
    packets = []
    base_time = datetime.now()
    
    # Create some flows with bidirectional traffic
    flows = [
        # TCP flow 1: Web traffic
        {
            'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8',
            'src_port': 12345, 'dst_port': 80, 'protocol': 6
        },
        # TCP flow 2: HTTPS traffic
        {
            'src_ip': '192.168.1.100', 'dst_ip': '1.1.1.1',
            'src_port': 54321, 'dst_port': 443, 'protocol': 6
        },
        # UDP flow 1: DNS traffic
        {
            'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8',
            'src_port': 45678, 'dst_port': 53, 'protocol': 17
        },
        # UDP flow 2: Custom UDP
        {
            'src_ip': '10.0.0.5', 'dst_ip': '10.0.0.10',
            'src_port': 9999, 'dst_port': 8888, 'protocol': 17
        }
    ]
    
    frame_num = 1
    
    for i in range(num_packets):
        # Select a random flow
        flow = flows[i % len(flows)]
        
        # Randomly decide direction (forward or backward)
        if np.random.random() > 0.3:  # 70% forward, 30% backward
            # Forward direction
            src_ip, dst_ip = flow['src_ip'], flow['dst_ip']
            src_port, dst_port = flow['src_port'], flow['dst_port']
        else:
            # Backward direction (swap source and destination)
            src_ip, dst_ip = flow['dst_ip'], flow['src_ip']
            src_port, dst_port = flow['dst_port'], flow['src_port']
        
        # Generate packet data
        packet = {
            'frame_num': frame_num,
            'timestamp': (base_time + timedelta(seconds=i * 0.1 + np.random.random() * 0.05)).timestamp(),
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'protocol': flow['protocol'],
            'size': np.random.randint(64, 1500),  # Random packet size
            'summary': f"{'TCP' if flow['protocol'] == 6 else 'UDP'} {src_ip}:{src_port} > {dst_ip}:{dst_port}"
        }
        
        packets.append(packet)
        frame_num += 1
    
    # Create DataFrame and save to CSV
    df = pd.DataFrame(packets)
    df.to_csv(filename, index=False)
    print(f"✅ Sample CSV created: {filename}")
    print(f"   Packets: {len(df)}")
    print(f"   Columns: {list(df.columns)}")
    
    # Show sample data
    print("\nSample packet data:")
    print(df.head().to_string(index=False))
    
    return filename

def test_csv_to_flows_conversion():
    """
    Test the CSV to flows conversion
    """
    print("\n" + "="*60)
    print("Testing CSV to Flows Conversion")
    print("="*60)
    
    # Create sample CSV
    sample_csv = create_sample_packet_csv("test_packets.csv", 50)
    
    # Test the conversion
    converter = CSVToFlowConverter()
    
    try:
        # Step 1: Read CSV
        print(f"\nStep 1: Reading CSV file...")
        packets_df = converter.read_csv_file(sample_csv)
        
        # Step 2: Convert to flows
        print(f"\nStep 2: Converting to flows...")
        flows_df = converter.convert_to_flows(packets_df)
        
        if flows_df is not None and len(flows_df) > 0:
            # Step 3: Save results
            print(f"\nStep 3: Saving results...")
            
            # Save to CSV
            output_csv = "test_flows.csv"
            converter.save_to_csv(flows_df, output_csv)
            
            # Save to JSON
            output_json = "test_flows.json"
            converter.save_to_json(flows_df, output_json)
            
            # Print summary
            print(f"\nStep 4: Results summary...")
            converter.print_flow_summary(flows_df)
            
            # Show sample flow data
            print(f"\nSample flow data:")
            required_columns = [
                'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
                'total_fwd_packets', 'total_bwd_packets', 'flow_duration',
                'total_fwd_bytes', 'total_bwd_bytes'
            ]
            print(flows_df[required_columns].head().to_string(index=False))
            
            print(f"\n✅ Test completed successfully!")
            print(f"📁 Output files:")
            print(f"   📊 Flows CSV: {output_csv}")
            print(f"   📊 Flows JSON: {output_json}")
            
            return True
        else:
            print("❌ No flows generated")
            return False
            
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False
    finally:
        # Cleanup test files
        for file in ["test_packets.csv", "test_flows.csv", "test_flows.json"]:
            if os.path.exists(file):
                try:
                    os.remove(file)
                    print(f"🧹 Cleaned up: {file}")
                except:
                    pass

def demonstrate_usage():
    """
    Demonstrate various usage scenarios
    """
    print("\n" + "="*60)
    print("CSV to Flows Converter - Usage Examples")
    print("="*60)
    
    print("\n1. Basic usage:")
    print("   python csv_to_flows.py packets.csv -o flows.csv")
    
    print("\n2. Save to all formats:")
    print("   python csv_to_flows.py packets.csv -o flows.csv --save-all")
    
    print("\n3. Custom JSON output:")
    print("   python csv_to_flows.py packets.csv -o flows.csv --json flows.json")
    
    print("\n4. Include database save:")
    print("   python csv_to_flows.py packets.csv -o flows.csv --database")
    
    print("\n5. Verbose output:")
    print("   python csv_to_flows.py packets.csv -o flows.csv --verbose")
    
    print("\nInput CSV format requirements:")
    print("  Required columns: timestamp, src_ip, src_port, dst_ip, dst_port, protocol, size")
    print("  Optional columns: frame_num, summary")
    
    print("\nOutput CSV format:")
    print("  Columns: src_ip, dst_ip, src_port, dst_port, protocol,")
    print("           total_fwd_packets, total_bwd_packets, flow_duration,")
    print("           total_fwd_bytes, total_bwd_bytes")
    
    print("\nKey features:")
    print("  ✅ Handles bidirectional flows correctly")
    print("  ✅ Converts timestamps to seconds automatically")
    print("  ✅ Groups by (src_ip, dst_ip, src_port, dst_port, protocol)")
    print("  ✅ Calculates forward/backward packets and bytes separately")
    print("  ✅ Supports both TCP and UDP protocols")
    print("  ✅ Saves to multiple formats (CSV, JSON, Database)")

if __name__ == "__main__":
    print("PyGuard CSV to Flows Converter - Test Suite")
    print("="*60)
    
    # Run the test
    success = test_csv_to_flows_conversion()
    
    # Show usage examples
    demonstrate_usage()
    
    if success:
        print(f"\n🎉 All tests passed! The converter is ready to use.")
    else:
        print(f"\n❌ Tests failed. Please check the implementation.")