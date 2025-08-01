"""
Tests for the packet processor module
"""

import unittest
from unittest.mock import MagicMock, patch
import socket
from datetime import datetime

from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, ARP, Raw

from pyguard.core.config import Config
from pyguard.core.packet_processor import PacketProcessor

class MockHeader:
    """Mock pcap header for testing"""
    
    def __init__(self, ts_sec=0, ts_usec=0, caplen=0, len=0):
        self.ts_sec = ts_sec
        self.ts_usec = ts_usec
        self.caplen = caplen
        self.len = len
    
    def getts(self):
        """Get timestamp tuple"""
        return (self.ts_sec, self.ts_usec)
    
    def getcaplen(self):
        """Get capture length"""
        return self.caplen
    
    def getlen(self):
        """Get packet length"""
        return self.len

class TestPacketProcessor(unittest.TestCase):
    """Test cases for the PacketProcessor class"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = Config()
        self.processor = PacketProcessor(self.config)
    
    def test_process_tcp_packet(self):
        """Test processing a TCP packet"""
        # Create a mock header
        header = MockHeader(
            ts_sec=1609459200,  # 2021-01-01 00:00:00
            ts_usec=123456,
            caplen=74,
            len=74
        )
        
        # Create a TCP packet
        packet = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
                 IP(src="192.168.1.1", dst="192.168.1.2") / \
                 TCP(sport=12345, dport=80, flags="S")
        
        # Process the packet
        metadata = self.processor.process_packet(header, packet)
        
        # Check basic metadata
        self.assertEqual(metadata["timestamp"], "2021-01-01T00:00:00.123456")
        self.assertEqual(metadata["timestamp_epoch"], 1609459200.123456)
        self.assertEqual(metadata["capture_length"], 74)
        self.assertEqual(metadata["packet_length"], 74)
        
        # Check Ethernet metadata
        self.assertEqual(metadata["mac_src"], "00:11:22:33:44:55")
        self.assertEqual(metadata["mac_dst"], "66:77:88:99:aa:bb")
        
        # Check IP metadata
        self.assertEqual(metadata["ip_version"], 4)
        self.assertEqual(metadata["src_ip"], "192.168.1.1")
        self.assertEqual(metadata["dst_ip"], "192.168.1.2")
        
        # Check TCP metadata
        self.assertEqual(metadata["protocol_name"], "TCP")
        self.assertEqual(metadata["src_port"], 12345)
        self.assertEqual(metadata["dst_port"], 80)
        self.assertIn("SYN", metadata["tcp_flags"])
    
    def test_process_udp_packet(self):
        """Test processing a UDP packet"""
        # Create a mock header
        header = MockHeader(
            ts_sec=1609459200,  # 2021-01-01 00:00:00
            ts_usec=123456,
            caplen=74,
            len=74
        )
        
        # Create a UDP packet
        packet = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
                 IP(src="192.168.1.1", dst="192.168.1.2") / \
                 UDP(sport=53, dport=12345)
        
        # Process the packet
        metadata = self.processor.process_packet(header, packet)
        
        # Check UDP metadata
        self.assertEqual(metadata["protocol_name"], "UDP")
        self.assertEqual(metadata["src_port"], 53)
        self.assertEqual(metadata["dst_port"], 12345)
    
    def test_process_icmp_packet(self):
        """Test processing an ICMP packet"""
        # Create a mock header
        header = MockHeader(
            ts_sec=1609459200,  # 2021-01-01 00:00:00
            ts_usec=123456,
            caplen=74,
            len=74
        )
        
        # Create an ICMP packet
        packet = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
                 IP(src="192.168.1.1", dst="192.168.1.2") / \
                 ICMP(type=8, code=0)  # Echo request
        
        # Process the packet
        metadata = self.processor.process_packet(header, packet)
        
        # Check ICMP metadata
        self.assertEqual(metadata["protocol_name"], "ICMP")
        self.assertEqual(metadata["icmp_type"], 8)
        self.assertEqual(metadata["icmp_code"], 0)
    
    def test_process_arp_packet(self):
        """Test processing an ARP packet"""
        # Create a mock header
        header = MockHeader(
            ts_sec=1609459200,  # 2021-01-01 00:00:00
            ts_usec=123456,
            caplen=74,
            len=74
        )
        
        # Create an ARP packet
        packet = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
                 ARP(hwsrc="00:11:22:33:44:55", hwdst="00:00:00:00:00:00",
                     psrc="192.168.1.1", pdst="192.168.1.2", op=1)  # ARP request
        
        # Process the packet
        metadata = self.processor.process_packet(header, packet)
        
        # Check ARP metadata
        self.assertEqual(metadata["protocol_name"], "ARP")
        self.assertEqual(metadata["arp_op"], 1)
        self.assertEqual(metadata["arp_op_name"], "request")
        self.assertEqual(metadata["arp_hwsrc"], "00:11:22:33:44:55")
        self.assertEqual(metadata["arp_psrc"], "192.168.1.1")
        self.assertEqual(metadata["arp_pdst"], "192.168.1.2")
    
    def test_process_dns_packet(self):
        """Test processing a DNS packet"""
        # Create a mock header
        header = MockHeader(
            ts_sec=1609459200,  # 2021-01-01 00:00:00
            ts_usec=123456,
            caplen=74,
            len=74
        )
        
        # Create a DNS query packet
        dns_query = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
                    IP(src="192.168.1.1", dst="8.8.8.8") / \
                    UDP(sport=12345, dport=53) / \
                    DNS(id=12345, qr=0, qd=DNSQR(qname="example.com"))
        
        # Process the packet
        metadata = self.processor.process_packet(header, dns_query)
        
        # Check DNS metadata
        self.assertIn("dns", metadata)
        self.assertEqual(metadata["dns"]["dns_id"], 12345)
        self.assertEqual(metadata["dns"]["dns_qr"], 0)
        self.assertEqual(metadata["dns"]["dns_query_type"], "query")
        self.assertEqual(metadata["dns"]["dns_query_name"], "example.com")
    
    @patch('socket.gethostbyname_ex')
    def test_determine_direction(self, mock_gethostbyname):
        """Test determining packet direction"""
        # Mock socket.gethostbyname_ex to return local IPs
        mock_gethostbyname.return_value = ('localhost', [], ['127.0.0.1', '192.168.1.100'])
        
        # Test outgoing packet
        self.assertEqual(self.processor._determine_direction("192.168.1.100"), "outgoing")
        
        # Test incoming packet
        self.assertEqual(self.processor._determine_direction("8.8.8.8"), "incoming")
        
        # Test loopback
        self.assertEqual(self.processor._determine_direction("127.0.0.1"), "outgoing")
    
    def test_extract_http_metadata(self):
        """Test extracting HTTP metadata"""
        # Create an HTTP request packet
        http_request = Ether() / IP() / TCP() / Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
        
        # Extract HTTP metadata
        http_metadata = self.processor._extract_http_metadata(http_request)
        
        # Check HTTP metadata
        self.assertIsNotNone(http_metadata)
        self.assertEqual(http_metadata["http"]["type"], "request")
        self.assertEqual(http_metadata["http"]["method"], "GET")
        self.assertEqual(http_metadata["http"]["path"], "/index.html")
        self.assertEqual(http_metadata["http"]["host"], "example.com")
        
        # Create an HTTP response packet
        http_response = Ether() / IP() / TCP() / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
        
        # Extract HTTP metadata
        http_metadata = self.processor._extract_http_metadata(http_response)
        
        # Check HTTP metadata
        self.assertIsNotNone(http_metadata)
        self.assertEqual(http_metadata["http"]["type"], "response")
        self.assertEqual(http_metadata["http"]["status_code"], 200)
        self.assertEqual(http_metadata["http"]["reason"], "OK")

if __name__ == "__main__":
    unittest.main()