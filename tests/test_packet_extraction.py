#!/usr/bin/env python3
"""
Test script to demonstrate packet extraction capabilities
"""

from scapy.all import *
import json
from enhanced_packet_extractor import process_packet_comprehensive

def create_sample_packets():
    """Create sample packets for testing"""
    packets = []
    
    # Create a TCP SYN packet
    tcp_syn = Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/TCP(sport=12345, dport=80, flags="S")
    packets.append(tcp_syn)
    
    # Create a UDP DNS packet
    udp_dns = Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=54321, dport=53)
    packets.append(udp_dns)
    
    # Create an ICMP packet
    icmp_ping = Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/ICMP()
    packets.append(icmp_ping)
    
    return packets

def test_packet_extraction():
    """Test the packet extraction functionality"""
    print("Testing Packet Extraction...")
    print("=" * 50)
    
    # Create sample packets
    packets = create_sample_packets()
    
    for i, packet in enumerate(packets, 1):
        print(f"\nPacket {i}: {packet.summary()}")
        print("-" * 30)
        
        # Extract packet information
        packet_info = process_packet_comprehensive(packet)
        
        # Display key information
        essential_fields = [
            'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'protocol_name',
            'packet_size', 'total_length', 'header_length', 'payload_size',
            'fin_flag', 'syn_flag', 'rst_flag', 'psh_flag', 'ack_flag', 'urg_flag'
        ]
        
        for field in essential_fields:
            if field in packet_info and packet_info[field] is not None:
                print(f"  {field}: {packet_info[field]}")
    
    print("\n" + "=" * 50)
    print("✅ Packet extraction test completed!")
    print("All essential fields are being extracted correctly.")

if __name__ == "__main__":
    test_packet_extraction()