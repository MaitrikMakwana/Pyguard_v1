"""
PyGuard Desktop Application - Advanced Network Packet Capture and Analysis
A Wireshark-like application for deep packet inspection, analysis, and filtering
"""

import sys
import os
import time
import logging
import threading
import socket
import struct
import json
import csv
import re
import queue
import ipaddress
from datetime import datetime
import random
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import tempfile
import binascii
from PyQt5.QtCore import QSettings
from PyQt5.QtGui import QFontDatabase

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('pyguard_desktop_simple.log')
    ]
)

def clean_unicode_for_csv(text):
    """Clean Unicode characters that cause CSV encoding issues on Windows"""
    if not isinstance(text, str):
        return str(text) if text is not None else ""
    
    # Replace problematic Unicode characters with ASCII equivalents
    replacements = {
        '\u2192': '->',   # Right arrow
        '\u2190': '<-',   # Left arrow
        '\u2194': '<->',  # Left-right arrow
        '\u21d2': '=>',   # Double right arrow
        '\u21d0': '<=',   # Double left arrow
        '\u2022': '*',    # Bullet point
        '\u2013': '-',    # En dash
        '\u2014': '--',   # Em dash
        '\u201c': '"',    # Left double quote
        '\u201d': '"',    # Right double quote
        '\u2018': "'",    # Left single quote
        '\u2019': "'",    # Right single quote
    }
    
    for unicode_char, replacement in replacements.items():
        text = text.replace(unicode_char, replacement)
    
    return text

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QComboBox, QTextEdit, QTabWidget, QSplitter,
    QGroupBox, QFormLayout, QCheckBox, QMessageBox, QInputDialog,
    QTableWidget, QTableWidgetItem, QHeaderView, QMenu, QAction,
    QFileDialog, QDialog, QRadioButton, QSpinBox, QTreeWidget, 
    QTreeWidgetItem, QProgressBar, QStatusBar, QLineEdit, QToolBar,
    QToolButton, QSizePolicy, QFrame, QTextBrowser, QProgressDialog,
    QScrollArea
)
from PyQt5.QtCore import QTimer, QSize, Qt
from PyQt5.QtGui import QFont, QColor, QCursor

class LogHandler(logging.Handler):
    """Custom log handler that writes to a QTextEdit widget"""
    
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        self.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    def emit(self, record):
        msg = self.format(record)
        self.text_widget.append(msg)

from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw, Dot1Q, sniff
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
# TLS import removed as it's not available in this version of scapy
import binascii

# IDS integration imports
try:
    import requests
except ImportError:
    requests = None
    logger.warning(
        "requests library not available - remote IDS service disabled (local Final_IDS pipeline will be used if available)"
    )

try:
    from .ids_service_manager import IDSServiceManager, IDSServiceError
    from .ids_analysis_widget import IDSAnalysisWidget
except ImportError:
    from ids_service_manager import IDSServiceManager, IDSServiceError  # type: ignore
    from ids_analysis_widget import IDSAnalysisWidget  # type: ignore


class IDSAnalysisWorker(QThread):
    """Background worker that sends PCAP data to the IDS service."""

    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, service_manager: IDSServiceManager, pcap_path: str) -> None:
        super().__init__()
        self.service_manager = service_manager
        self.pcap_path = pcap_path

    def run(self) -> None:
        try:
            results = self.service_manager.analyze_pcap(self.pcap_path)
        except IDSServiceError as exc:
            self.error.emit(str(exc))
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.exception("Unexpected IDS analysis error: %s", exc)
            self.error.emit(str(exc))
        else:
            self.finished.emit(results)


class PacketCapture(QThread):
    """Thread for capturing network packets with deep protocol inspection using scapy"""
    
    # Define signals
    packet_captured = pyqtSignal(dict)
    status_update = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, interface, filter_expression=""):
        super().__init__()
        self.interface = interface
        self.filter_expression = filter_expression
        self.running = False
        self.daemon = True  # Thread will exit when main program exits
        
        # Statistics
        self.stats = {
            "packets_captured": 0,
            "bytes_captured": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "http_packets": 0,
            "dns_packets": 0,
            "arp_packets": 0,
            "ethernet_packets": 0,
            "ipv4_packets": 0,
            "ipv6_packets": 0,
            "start_time": None
        }
    
    def run(self):
        """Main thread function"""
        try:
            logger.info(f"Starting packet capture on interface {self.interface}")
            self.running = True
            self.stats["start_time"] = time.time()
            
            try:
                # Use scapy's sniff function for packet capture
                logger.info(f"Starting capture on interface {self.interface} with filter: {self.filter_expression}")
                
                # Start sniffing packets with timeout-based stopping
                while self.running:
                    try:
                        sniff(
                            iface=self.interface,
                            filter=self.filter_expression if self.filter_expression else None,
                            prn=self._packet_callback,
                            store=0,  # Don't store packets in memory
                            timeout=1,  # Timeout after 1 second to check running status
                            count=100  # Process up to 100 packets before checking running status
                        )
                    except Exception as sniff_error:
                        if self.running:  # Only log if we're still supposed to be running
                            logger.error(f"Error in sniff loop: {sniff_error}")
                        break
                
            except Exception as e:
                logger.error(f"Error starting packet capture: {e}")
                self.error_occurred.emit(f"Error starting capture: {e}")
                
                # Fall back to simulation mode for testing
                logger.info("Falling back to simulation mode")
                while self.running:
                    # Create a simulated packet
                    packet = self._create_simulated_packet()
                    
                    # Update statistics
                    self.stats["packets_captured"] += 1
                    self.stats["bytes_captured"] += packet["size"]
                    
                    if packet["protocol"] == "TCP":
                        self.stats["tcp_packets"] += 1
                    elif packet["protocol"] == "UDP":
                        self.stats["udp_packets"] += 1
                    elif packet["protocol"] == "ICMP":
                        self.stats["icmp_packets"] += 1
                    
                    # Emit signals
                    self.packet_captured.emit(packet)
                    self.status_update.emit(self.stats)
                    
                    # Sleep to simulate packet arrival rate
                    time.sleep(0.1)
        
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            self.error_occurred.emit(str(e))
        
        finally:
            self.running = False
            logger.info("Packet capture stopped")
    
    def stop(self):
        """Stop the capture thread"""
        logger.info("Stopping packet capture thread...")
        self.running = False
        
        # Give the thread a moment to stop gracefully
        if self.isRunning():
            self.wait(2000)  # Wait up to 2 seconds
            
        # If thread is still running, terminate it forcefully
        if self.isRunning():
            logger.warning("Thread did not stop gracefully, terminating...")
            self.terminate()
            self.wait(1000)  # Wait for termination
    
    def _packet_callback(self, packet):
        """Process a captured packet from scapy's sniff function"""
        if not self.running:
            return
        
        try:
            # Process the packet
            packet_info = self._process_packet(packet)
            
            if packet_info:
                # Update statistics
                self.stats["packets_captured"] += 1
                self.stats["bytes_captured"] += packet_info["size"]
                
                # Update protocol-specific counters
                if packet_info.get("protocol") == "TCP":
                    self.stats["tcp_packets"] += 1
                elif packet_info.get("protocol") == "UDP":
                    self.stats["udp_packets"] += 1
                elif packet_info.get("protocol") == "ICMP":
                    self.stats["icmp_packets"] += 1
                
                if "HTTP" in packet_info.get("layers", []):
                    self.stats["http_packets"] += 1
                if "DNS" in packet_info.get("layers", []):
                    self.stats["dns_packets"] += 1
                if "ARP" in packet_info.get("layers", []):
                    self.stats["arp_packets"] += 1
                if "Ethernet" in packet_info.get("layers", []):
                    self.stats["ethernet_packets"] += 1
                if "IPv4" in packet_info.get("layers", []):
                    self.stats["ipv4_packets"] += 1
                if "IPv6" in packet_info.get("layers", []):
                    self.stats["ipv6_packets"] += 1
                
                # Emit signals
                self.packet_captured.emit(packet_info)
                self.status_update.emit(self.stats)
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _process_packet(self, packet):
        """Process a captured packet and extract metadata"""
        try:
            # Initialize metadata dictionary
            metadata = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
                "size": len(packet),
                "layers": [],  # Track all layers found in the packet
                "protocol_tree": [],  # Detailed protocol tree
                "packet_data": bytes(packet)  # Store raw packet data for PCAP export
            }
            
            # Extract Ethernet layer metadata
            if Ether in packet:
                metadata.update({
                    "mac_src": packet[Ether].src,
                    "mac_dst": packet[Ether].dst,
                    "eth_type": packet[Ether].type
                })
                metadata["layers"].append("Ethernet")
            
            # Check for VLAN tagging
            if Dot1Q in packet:
                metadata.update({
                    "vlan_id": packet[Dot1Q].vlan,
                    "vlan_priority": packet[Dot1Q].prio
                })
                metadata["layers"].append("VLAN")
            
            # Extract IP layer metadata
            if IP in packet:
                metadata.update({
                    "src_ip": packet[IP].src,
                    "dst_ip": packet[IP].dst,
                    "ttl": packet[IP].ttl,
                    "ip_id": packet[IP].id,
                    "ip_len": packet[IP].len,
                    "ip_version": 4
                })
                metadata["layers"].append("IPv4")
            elif IPv6 in packet:
                metadata.update({
                    "src_ip": packet[IPv6].src,
                    "dst_ip": packet[IPv6].dst,
                    "hop_limit": packet[IPv6].hlim,
                    "ip_version": 6
                })
                metadata["layers"].append("IPv6")
            
            # Extract transport layer metadata
            if TCP in packet:
                metadata.update({
                    "protocol": "TCP",
                    "src_port": packet[TCP].sport,
                    "dst_port": packet[TCP].dport,
                    "seq": packet[TCP].seq,
                    "ack": packet[TCP].ack,
                    "window": packet[TCP].window
                })
                
                # Extract TCP flags
                flags = []
                if packet[TCP].flags & 0x01:  # FIN
                    flags.append("FIN")
                if packet[TCP].flags & 0x02:  # SYN
                    flags.append("SYN")
                if packet[TCP].flags & 0x04:  # RST
                    flags.append("RST")
                if packet[TCP].flags & 0x08:  # PSH
                    flags.append("PSH")
                if packet[TCP].flags & 0x10:  # ACK
                    flags.append("ACK")
                if packet[TCP].flags & 0x20:  # URG
                    flags.append("URG")
                if packet[TCP].flags & 0x40:  # ECE
                    flags.append("ECE")
                if packet[TCP].flags & 0x80:  # CWR
                    flags.append("CWR")
                
                metadata["tcp_flags"] = flags
                metadata["layers"].append("TCP")
                
                # Check for HTTP
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    if Raw in packet:
                        try:
                            raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
                            if raw_data.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')) or \
                               raw_data.startswith(('HTTP/1.0 ', 'HTTP/1.1 ', 'HTTP/2 ')):
                                metadata["http_data"] = raw_data.split('\r\n\r\n')[0]  # Just headers
                                metadata["layers"].append("HTTP")
                        except:
                            pass
                
                # Check for TLS/SSL based on port numbers
                if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    metadata["layers"].append("TLS/SSL")
            
            elif UDP in packet:
                metadata.update({
                    "protocol": "UDP",
                    "src_port": packet[UDP].sport,
                    "dst_port": packet[UDP].dport,
                    "length": packet[UDP].len
                })
                metadata["layers"].append("UDP")
                
                # Check for DNS
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    if DNS in packet:
                        dns = packet[DNS]
                        metadata["dns"] = {
                            "id": dns.id,
                            "qr": dns.qr,  # 0 for query, 1 for response
                            "opcode": dns.opcode,
                            "query_type": "query" if dns.qr == 0 else "response"
                        }
                        
                        # Extract query information
                        if dns.qd and hasattr(dns.qd, "qname"):
                            metadata["dns"]["query_name"] = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                        
                        metadata["layers"].append("DNS")
            
            elif ICMP in packet:
                metadata.update({
                    "protocol": "ICMP",
                    "icmp_type": packet[ICMP].type,
                    "icmp_code": packet[ICMP].code
                })
                metadata["layers"].append("ICMP")
            
            elif ARP in packet:
                metadata.update({
                    "protocol": "ARP",
                    "arp_op": packet[ARP].op,
                    "arp_hwsrc": packet[ARP].hwsrc,
                    "arp_hwdst": packet[ARP].hwdst,
                    "arp_psrc": packet[ARP].psrc,
                    "arp_pdst": packet[ARP].pdst
                })
                metadata["layers"].append("ARP")
            
            # Generate detailed protocol tree
            metadata["protocol_tree"] = self._generate_protocol_tree(packet)
            
            # Generate Wireshark-like summary
            metadata["summary"] = self._generate_packet_summary(packet, metadata)
            
            # Add hex dump of packet
            metadata["hex_dump"] = self._generate_hex_dump(bytes(packet))
            
            return metadata
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            return None
    
    def _generate_protocol_tree(self, packet):
        """Generate a detailed protocol tree for deep inspection"""
        tree = []
        
        # Process each layer in the packet
        current_layer = packet
        while current_layer:
            layer_name = current_layer.name
            layer_fields = {}
            
            # Extract all fields from the current layer
            if hasattr(current_layer, 'fields'):
                for field_name, field_value in current_layer.fields.items():
                    # Convert bytes to string or hex as appropriate
                    if isinstance(field_value, bytes):
                        try:
                            layer_fields[field_name] = field_value.decode('utf-8', errors='replace')
                        except:
                            layer_fields[field_name] = f"0x{field_value.hex()}"
                    else:
                        layer_fields[field_name] = str(field_value)
            
            # Add layer to tree
            tree.append({
                "layer": layer_name,
                "fields": layer_fields
            })
            
            # Move to the next layer (payload)
            if hasattr(current_layer, 'payload') and current_layer.payload:
                current_layer = current_layer.payload
                # Skip Raw layer if it's just padding or not meaningful
                if current_layer.name == 'Raw' and len(current_layer.fields.get('load', b'')) <= 2:
                    break
            else:
                break
        
        return tree
    
    def _generate_packet_summary(self, packet, metadata):
        """Generate a Wireshark-like packet summary"""
        summary = ""
        
        # Start with protocol
        if "protocol" in metadata:
            protocol = metadata["protocol"]
        elif "layers" in metadata and metadata["layers"]:
            protocol = metadata["layers"][-1]  # Use the highest layer
        else:
            protocol = "Unknown"
        
        # Add source and destination
        if "src_ip" in metadata and "dst_ip" in metadata:
            src = metadata["src_ip"]
            dst = metadata["dst_ip"]
            
            # Add ports for TCP/UDP
            if "src_port" in metadata and "dst_port" in metadata:
                src += f":{metadata['src_port']}"
                dst += f":{metadata['dst_port']}"
            
            summary += f"{src} → {dst}"
        elif "mac_src" in metadata and "mac_dst" in metadata:
            summary += f"{metadata['mac_src']} → {metadata['mac_dst']}"
        
        # Add protocol-specific information
        if protocol == "TCP":
            # Add TCP flags
            if "tcp_flags" in metadata:
                flags_str = " ".join(metadata["tcp_flags"])
                summary += f" [{flags_str}]"
            
            # Add sequence/ack information
            if "seq" in metadata and "ack" in metadata:
                summary += f" Seq={metadata['seq']} Ack={metadata['ack']}"
            
            # Add window size
            if "window" in metadata:
                summary += f" Win={metadata['window']}"
        
        elif protocol == "UDP":
            if "length" in metadata:
                summary += f" Len={metadata['length']}"
        
        elif protocol == "ICMP":
            if "icmp_type" in metadata and "icmp_code" in metadata:
                icmp_types = {
                    0: "Echo Reply",
                    3: "Destination Unreachable",
                    5: "Redirect",
                    8: "Echo Request",
                    11: "Time Exceeded"
                }
                icmp_type = metadata["icmp_type"]
                icmp_type_name = icmp_types.get(icmp_type, f"Type {icmp_type}")
                summary += f" {icmp_type_name}"
        
        elif protocol == "ARP":
            if "arp_op" in metadata:
                op = metadata["arp_op"]
                op_name = "request" if op == 1 else "reply" if op == 2 else f"op {op}"
                summary += f" {op_name}"
                
                if "arp_psrc" in metadata and "arp_pdst" in metadata:
                    if op == 1:  # request
                        summary += f" who-has {metadata['arp_pdst']} tell {metadata['arp_psrc']}"
                    elif op == 2:  # reply
                        summary += f" {metadata['arp_psrc']} is-at {metadata['arp_hwsrc']}"
        
        # Add length information if not already added
        if "size" in metadata and not "Len=" in summary:
            summary += f" Length: {metadata['size']} bytes"
        
        # Prepend protocol to summary
        summary = f"{protocol}: {summary}"
        
        return summary
    
    def _generate_hex_dump(self, packet_data, bytes_per_line=16):
        """Generate a hexadecimal dump of the packet data"""
        hex_dump = ""
        
        for i in range(0, len(packet_data), bytes_per_line):
            # Get a chunk of bytes
            chunk = packet_data[i:i+bytes_per_line]
            
            # Convert to hex representation
            hex_values = ' '.join(f"{b:02x}" for b in chunk)
            
            # Convert to ASCII representation (printable chars only)
            ascii_values = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            
            # Add line to hex dump
            hex_dump += f"{i:04x}:  {hex_values.ljust(bytes_per_line*3)}  {ascii_values}\n"
        
        return hex_dump
    
    def _create_simulated_packet(self):
        """Create a simulated packet for testing"""
        protocols = ["TCP", "UDP", "ICMP", "ARP"]
        protocol = random.choice(protocols)
        
        src_ip = f"192.168.1.{random.randint(1, 254)}"
        dst_ip = f"192.168.1.{random.randint(1, 254)}"
        
        src_port = random.randint(1024, 65535) if protocol in ["TCP", "UDP"] else None
        dst_port = random.choice([80, 443, 53, 22, 8080]) if protocol in ["TCP", "UDP"] else None
        
        size = random.randint(64, 1500)
        
        packet = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "size": size,
            "layers": ["Ethernet", "IPv4", protocol],
            "summary": f"{protocol}: {src_ip}:{src_port if src_port else ''} → {dst_ip}:{dst_port if dst_port else ''}"
        }
        
        # Add protocol-specific fields
        if protocol == "TCP":
            flags = []
            if random.random() < 0.2:
                flags.append("SYN")
            if random.random() < 0.5:
                flags.append("ACK")
            if random.random() < 0.1:
                flags.append("FIN")
            if random.random() < 0.05:
                flags.append("RST")
            packet["tcp_flags"] = flags
            
            # Simulate HTTP for some TCP packets
            if dst_port == 80 or src_port == 80:
                if random.random() < 0.5:
                    packet["layers"].append("HTTP")
                    if random.random() < 0.5:
                        packet["http_data"] = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: PyGuard/1.0\r\n"
                    else:
                        packet["http_data"] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1024\r\n"
        
        elif protocol == "ICMP":
            packet["icmp_type"] = random.randint(0, 8)
            packet["icmp_code"] = random.randint(0, 3)
        
        elif protocol == "UDP":
            # Simulate DNS for some UDP packets
            if dst_port == 53 or src_port == 53:
                packet["layers"].append("DNS")
                packet["dns"] = {
                    "id": random.randint(1, 65535),
                    "qr": random.choice([0, 1]),
                    "query_type": "query" if packet["dns"]["qr"] == 0 else "response",
                    "query_name": random.choice(["example.com", "google.com", "github.com", "microsoft.com"])
                }
        
        elif protocol == "ARP":
            packet["arp_op"] = random.choice([1, 2])  # 1=request, 2=reply
            packet["arp_hwsrc"] = f"00:11:22:33:44:{random.randint(0, 99):02d}"
            packet["arp_hwdst"] = "ff:ff:ff:ff:ff:ff" if packet["arp_op"] == 1 else f"00:11:22:33:44:{random.randint(0, 99):02d}"
            packet["arp_psrc"] = src_ip
            packet["arp_pdst"] = dst_ip
        
        # Add simulated hex dump
        packet["hex_dump"] = f"0000:  00 11 22 33 44 55 66 77 88 99 aa bb 08 00 45 00  ..\"3DUfw......E.\n" + \
                            f"0010:  00 3c 00 01 00 00 40 06 7c cd {src_ip.replace('.', ' ')}  .<....@.|.......\n" + \
                            f"0020:  {dst_ip.replace('.', ' ')} {src_port:04x} {dst_port:04x} 00 00 00 00 00 00 00 00  .......P..........\n" + \
                            f"0030:  50 02 20 00 f9 9b 00 00 00 00 00 00 00 00         P. .............\n"
        
        # Add simulated protocol tree
        packet["protocol_tree"] = [
            {"layer": "Ethernet", "fields": {"src": "00:11:22:33:44:55", "dst": "66:77:88:99:aa:bb", "type": "IPv4"}},
            {"layer": "IPv4", "fields": {"src": src_ip, "dst": dst_ip, "ttl": "64", "proto": protocol}},
        ]
        
        if protocol == "TCP":
            packet["protocol_tree"].append({
                "layer": "TCP", 
                "fields": {
                    "sport": str(src_port), 
                    "dport": str(dst_port), 
                    "flags": " ".join(packet["tcp_flags"])
                }
            })
        elif protocol == "UDP":
            packet["protocol_tree"].append({
                "layer": "UDP", 
                "fields": {"sport": str(src_port), "dport": str(dst_port), "len": str(size - 42)}
            })
        elif protocol == "ICMP":
            packet["protocol_tree"].append({
                "layer": "ICMP", 
                "fields": {"type": str(packet["icmp_type"]), "code": str(packet["icmp_code"])}
            })
        elif protocol == "ARP":
            packet["protocol_tree"].append({
                "layer": "ARP", 
                "fields": {
                    "op": "1 (request)" if packet["arp_op"] == 1 else "2 (reply)",
                    "hwsrc": packet["arp_hwsrc"],
                    "hwdst": packet["arp_hwdst"],
                    "psrc": packet["arp_psrc"],
                    "pdst": packet["arp_pdst"]
                }
            })
        
        return packet

class DesktopApp(QMainWindow):
    """Desktop UI for PyGuard network packet capture and filtering"""
    
    def __init__(self):
        super().__init__()
        
        self.capture_thread = None
        self.captured_packets = []
        self.packet_queue = queue.Queue()
        self.processing_thread = None
        self.is_processing = False
        
        # Default display settings
        self.max_display_packets = 100000  # Maximum number of packets to display
        self.packet_buffer_size = 1000  # Process packets in batches
        self.display_update_interval = 100  # ms
        
        # Try to load display settings from config.yaml
        self.load_display_config()
        
        self.selected_interface = None  # Store the selected interface name
        
        # Protocol statistics
        self.protocol_stats = {
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "arp_packets": 0,
            "dns_packets": 0,
            "http_packets": 0,
            "other_packets": 0
        }
        
        # Setup UI
        self.setWindowTitle("PyGuard Desktop - Packet Capture & Analysis")
        self.setGeometry(100, 100, 1280, 800)  # Larger default window size
        
        # Set application style for better appearance
        QApplication.setStyle("Fusion")
        
        # Set up application-wide font
        self.setup_fonts()

        # Initialize ML Analysis
        self.ml_inference_available = False

        # IDS integration setup
        self.ids_service_manager: Optional[IDSServiceManager] = None
        self.ids_backend_available = False
        try:
            self.ids_service_manager = IDSServiceManager()
            self.ids_backend_available = self.ids_service_manager.has_any_backend
        except Exception as exc:
            logger.warning("IDS integration disabled: %s", exc)

        # Initialize UI
        self.init_ui()
        self.ids_analysis_widget: Optional[IDSAnalysisWidget] = None
        self.ids_last_results: Optional[Dict] = None
        self.ids_analysis_worker: Optional[IDSAnalysisWorker] = None
        self.ids_progress_dialog: Optional[QProgressDialog] = None
        self.ids_temp_pcap_path: Optional[str] = None

    def load_display_config(self) -> None:
        """Load optional display configuration; fall back to defaults if unavailable."""
        config_path = Path("config.yaml")
        if not config_path.exists():
            return

        try:
            import yaml
        except ImportError:
            logger.warning("yaml library not available; skipping display configuration load.")
            return

        try:
            with config_path.open("r", encoding="utf-8") as handle:
                config = yaml.safe_load(handle) or {}
        except Exception as exc:  # pragma: no cover - config optional
            logger.warning("Failed to load display configuration: %s", exc)
            return

        display_cfg = config.get("display", {})
        self.max_display_packets = int(display_cfg.get("max_packets", self.max_display_packets))
        self.packet_buffer_size = int(display_cfg.get("packet_buffer_size", self.packet_buffer_size))
        self.display_update_interval = int(display_cfg.get("display_update_interval", self.display_update_interval))
        
    def setup_fonts(self):
        """Set up application-wide fonts for better readability"""
        # Create a larger base font for the entire application
        app_font = QApplication.font()
        app_font.setPointSize(12)  # Increase from default (usually 8 or 9)
        QApplication.setFont(app_font)
        
        # Create a monospace font for code/data display
        # Create an instance of QFontDatabase first
        font_db = QFontDatabase()
        mono_families = font_db.families()
        mono_font = None
        
        # Try to find a good monospace font
        preferred_mono = ["Consolas", "DejaVu Sans Mono", "Courier New", "Monospace"]
        for family in preferred_mono:
            if family in mono_families:
                mono_font = QFont(family)
                mono_font.setPointSize(12)  # Larger monospace font
                break
        
        # If no preferred font found, use Courier New as fallback
        if not mono_font:
            mono_font = QFont("Courier New")
            mono_font.setPointSize(12)
                
        # Store the monospace font for later use
        self.mono_font = mono_font
    
    def init_ui(self):
        """Initialize the user interface"""
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main toolbar
        self.toolbar = QToolBar("Main Toolbar")
        self.toolbar.setIconSize(QSize(24, 24))
        self.toolbar.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        self.addToolBar(self.toolbar)
        
        # Create capture control group
        capture_label = QLabel("Capture:")
        capture_label.setStyleSheet("font-weight: bold;")
        self.toolbar.addWidget(capture_label)
        
        # Add toolbar actions with better styling
        start_action = QAction("▶ Start", self)
        start_action.setToolTip("Start packet capture")
        start_action.triggered.connect(self.start_capture)
        self.toolbar.addAction(start_action)
        
        stop_action = QAction("⏹ Stop", self)
        stop_action.setToolTip("Stop packet capture")
        stop_action.triggered.connect(self.stop_capture)
        self.toolbar.addAction(stop_action)
        
        restart_action = QAction("⟳ Restart", self)
        restart_action.setToolTip("Restart packet capture")
        restart_action.triggered.connect(self.restart_capture)
        self.toolbar.addAction(restart_action)
        
        self.toolbar.addSeparator()
        
        # Create file operations group
        file_label = QLabel("File:")
        file_label.setStyleSheet("font-weight: bold;")
        self.toolbar.addWidget(file_label)
        
        open_action = QAction("📂 Open", self)
        open_action.setToolTip("Open saved packet files (PCAP, CSV, JSON)")
        open_action.triggered.connect(self.open_file)
        self.toolbar.addAction(open_action)
        
        save_action = QAction("💾 Save", self)
        save_action.setToolTip("Save captured packets")
        save_action.triggered.connect(self.save_packets)
        self.toolbar.addAction(save_action)

        self.analyze_ids_action = QAction("🔍 Analyze with IDS", self)
        self.analyze_ids_action.setToolTip("Send captured packets to IDS for attack detection")
        self.analyze_ids_action.triggered.connect(self.analyze_with_ids)
        self.toolbar.addAction(self.analyze_ids_action)
        self.analyze_ids_action.setEnabled(self.ids_backend_available)
        
        clear_action = QAction("🗑 Clear", self)
        clear_action.setToolTip("Clear display")
        clear_action.triggered.connect(self.clear_display)
        self.toolbar.addAction(clear_action)
        
        self.toolbar.addSeparator()
        
        # Create display options group
        display_label = QLabel("Display:")
        display_label.setStyleSheet("font-weight: bold;")
        self.toolbar.addWidget(display_label)
        
        # Add packet limit control with a more descriptive label
        limit_label = QLabel("Display Limit:")
        limit_label.setToolTip("Maximum number of packets to keep in the display")
        self.toolbar.addWidget(limit_label)
        
        self.packet_limit_combo = QComboBox()
        self.packet_limit_combo.addItems([
            "1,000 packets", 
            "10,000 packets", 
            "100,000 packets", 
            "1,000,000 packets", 
            "Unlimited"
        ])
        
        # Set the combo box to match the config value
        if self.max_display_packets == float('inf'):
            self.packet_limit_combo.setCurrentText("Unlimited")
        else:
            # Find the closest match to the configured value
            if self.max_display_packets <= 1000:
                self.packet_limit_combo.setCurrentIndex(0)  # 1,000
            elif self.max_display_packets <= 10000:
                self.packet_limit_combo.setCurrentIndex(1)  # 10,000
            elif self.max_display_packets <= 100000:
                self.packet_limit_combo.setCurrentIndex(2)  # 100,000
            elif self.max_display_packets <= 1000000:
                self.packet_limit_combo.setCurrentIndex(3)  # 1,000,000
            else:
                self.packet_limit_combo.setCurrentText("Unlimited")
        self.packet_limit_combo.currentTextChanged.connect(self.set_packet_limit)
        self.packet_limit_combo.setToolTip("Set maximum number of packets to keep in the display.\nWhen this limit is reached, older packets will be removed.")
        self.packet_limit_combo.setFixedWidth(150)
        self.toolbar.addWidget(self.packet_limit_combo)
        
        # Add auto-scroll option
        self.toolbar.addSeparator()
        
        self.autoscroll_checkbox = QCheckBox("Auto-scroll")
        self.autoscroll_checkbox.setChecked(True)
        self.autoscroll_checkbox.setToolTip("Automatically scroll to show new packets")
        self.toolbar.addWidget(self.autoscroll_checkbox)
        
        # Add color legend button
        self.toolbar.addSeparator()
        
        color_legend_action = QAction("🎨 Color Legend", self)
        color_legend_action.setToolTip("Show packet color legend")
        color_legend_action.triggered.connect(self.show_color_legend)
        self.toolbar.addAction(color_legend_action)
        
        # Create main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Create top controls area
        top_controls = QHBoxLayout()
        
        # Create a minimal, clean top control bar
        # Use a simple horizontal layout without group boxes for a cleaner look
        
        # Interface selection label and combo
        interface_label = QLabel("Interface:")
        interface_label.setStyleSheet("font-weight: bold; font-size: 12pt;")
        top_controls.addWidget(interface_label)
        
        # Interface selection combo box
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumHeight(36)  # Taller for better touch targets
        self.interface_combo.setFont(QFont(QApplication.font().family(), 12))
        self.populate_interfaces()
        self.interface_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        top_controls.addWidget(self.interface_combo, 1)
        
        # Add some spacing
        top_controls.addSpacing(20)
        
        # Start button - larger and with better styling
        self.start_button = QPushButton("Start")
        self.start_button.setMinimumHeight(36)
        self.start_button.setMinimumWidth(100)
        self.start_button.setFont(QFont(QApplication.font().family(), 12))
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        self.start_button.clicked.connect(self.start_capture)
        top_controls.addWidget(self.start_button)
        
        # Stop button - larger and with better styling
        self.stop_button = QPushButton("Stop")
        self.stop_button.setMinimumHeight(36)
        self.stop_button.setMinimumWidth(100)
        self.stop_button.setFont(QFont(QApplication.font().family(), 12))
        self.stop_button.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        self.stop_button.clicked.connect(self.stop_capture)
        self.stop_button.setEnabled(False)
        top_controls.addWidget(self.stop_button)
        
        # Add some spacing at the end
        top_controls.addSpacing(10)
        
        main_layout.addLayout(top_controls)
        
        # Create a minimal, clean filter area
        filter_layout = QHBoxLayout()
        filter_layout.setContentsMargins(10, 10, 10, 10)  # More spacing for cleaner look
        filter_layout.setSpacing(10)  # More space between elements
        
        # Add filter label with larger font
        filter_label = QLabel("Filter:")
        filter_label.setStyleSheet("font-weight: bold; font-size: 12pt;")
        filter_layout.addWidget(filter_label)
        
        # Filter text input with better styling and larger font
        self.filter_text = QLineEdit()
        self.filter_text.setPlaceholderText("Enter filter expression (e.g., 'tcp', 'port 80', 'host 192.168.1.1')")
        self.filter_text.setMinimumHeight(36)  # Taller for better visibility
        self.filter_text.setFont(QFont(QApplication.font().family(), 12))
        self.filter_text.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: white;
            }
            QLineEdit:focus {
                border: 1px solid #2196F3;
            }
        """)
        self.filter_text.returnPressed.connect(self.apply_filter)  # Apply filter on Enter key
        filter_layout.addWidget(self.filter_text, 1)  # Give filter text stretch priority
        
        # Apply filter button with better styling
        self.apply_filter_button = QPushButton("Apply")
        self.apply_filter_button.setMinimumHeight(36)
        self.apply_filter_button.setMinimumWidth(80)
        self.apply_filter_button.setFont(QFont(QApplication.font().family(), 12))
        self.apply_filter_button.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0b7dda;
            }
        """)
        self.apply_filter_button.clicked.connect(self.apply_filter)
        filter_layout.addWidget(self.apply_filter_button)
        
        # Clear filter button with better styling
        self.clear_filter_button = QPushButton("Clear")
        self.clear_filter_button.setMinimumHeight(36)
        self.clear_filter_button.setMinimumWidth(80)
        self.clear_filter_button.setFont(QFont(QApplication.font().family(), 12))
        self.clear_filter_button.setStyleSheet("""
            QPushButton {
                background-color: #757575;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #616161;
            }
        """)
        self.clear_filter_button.clicked.connect(self.clear_filter)
        filter_layout.addWidget(self.clear_filter_button)
        
        # Add filter help button - larger for better visibility
        self.filter_help_button = QPushButton("?")
        self.filter_help_button.setFixedSize(36, 36)  # Larger button
        self.filter_help_button.setFont(QFont(QApplication.font().family(), 12, QFont.Bold))
        self.filter_help_button.setStyleSheet("""
            QPushButton {
                border-radius: 18px;
                background-color: #2196F3;
                color: white;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0b7dda;
            }
        """)
        self.filter_help_button.clicked.connect(self.show_filter_help)
        filter_layout.addWidget(self.filter_help_button)
        
        main_layout.addLayout(filter_layout)
        
        # Create main splitter for packet list and details - fully resizable
        self.main_splitter = QSplitter(self)
        self.main_splitter.setOrientation(1)  # Vertical orientation
        self.main_splitter.setChildrenCollapsible(False)  # Prevent sections from being collapsed completely
        self.main_splitter.setHandleWidth(8)  # Wider handle for easier grabbing
        self.main_splitter.setOpaqueResize(True)  # Resize content during dragging for better feedback
        
        # Create packet list table with better styling and larger fonts
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(7)
        self.packet_table.setHorizontalHeaderLabels(["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.setSelectionMode(QTableWidget.SingleSelection)
        self.packet_table.itemSelectionChanged.connect(self.on_packet_selected)
        self.packet_table.setAlternatingRowColors(True)
        
        # Set larger row height for better readability
        self.packet_table.verticalHeader().setDefaultSectionSize(36)
        
        # Set font for table
        table_font = QFont(QApplication.font().family(), 12)
        self.packet_table.setFont(table_font)
        
        # Apply monospace font to the table for better alignment
        if hasattr(self, 'mono_font'):
            self.packet_table.setFont(self.mono_font)
        
        # Improved styling with better spacing and larger fonts
        self.packet_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #e0e0e0;
                selection-background-color: #2196F3;
                selection-color: white;
                alternate-background-color: #f9f9f9;
                border: none;
            }
            QHeaderView::section {
                background-color: #f0f0f0;
                padding: 10px 5px;
                border: none;
                border-bottom: 1px solid #d0d0d0;
                font-weight: bold;
                font-size: 12pt;
            }
            QTableWidget::item {
                padding: 5px;
                border-bottom: 1px solid #f0f0f0;
            }
        """)
        
        # Set column widths
        self.packet_table.setColumnWidth(0, 60)  # No.
        self.packet_table.setColumnWidth(1, 120)  # Time
        self.packet_table.setColumnWidth(2, 150)  # Source
        self.packet_table.setColumnWidth(3, 150)  # Destination
        self.packet_table.setColumnWidth(4, 80)  # Protocol
        self.packet_table.setColumnWidth(5, 60)  # Length
        
        # Add right-click context menu
        self.packet_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.packet_table.customContextMenuRequested.connect(self.show_packet_context_menu)
        
        # Create horizontal splitter for packet details
        self.horizontal_details_splitter = QSplitter(Qt.Horizontal)
        self.horizontal_details_splitter.setChildrenCollapsible(False)
        self.horizontal_details_splitter.setHandleWidth(8)
        self.horizontal_details_splitter.setOpaqueResize(True)
        
        # Create details pane with tabs and better styling
        self.details_tabs = QTabWidget()
        self.details_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #c0c0c0;
                background: white;
            }
            QTabBar::tab {
                background: #e0e0e0;
                border: 1px solid #c0c0c0;
                padding: 6px 12px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #f0f0f0;
                border-bottom-color: #f0f0f0;
            }
        """)
        
        # Packet details tree with better styling and larger fonts
        self.packet_tree = QTreeWidget()
        self.packet_tree.setHeaderLabels(["Field", "Value"])
        self.packet_tree.header().setSectionResizeMode(QHeaderView.Interactive)
        self.packet_tree.header().setStretchLastSection(True)
        self.packet_tree.setAlternatingRowColors(True)
        
        # Set larger row height for better readability
        self.packet_tree.setIconSize(QSize(16, 16))
        
        # Apply monospace font to the tree for better alignment of values
        if hasattr(self, 'mono_font'):
            self.packet_tree.setFont(self.mono_font)
        else:
            tree_font = QFont(QApplication.font().family(), 12)
            self.packet_tree.setFont(tree_font)
        
        # Set header font
        header_font = QFont(QApplication.font().family(), 12, QFont.Bold)
        self.packet_tree.headerItem().setFont(0, header_font)
        self.packet_tree.headerItem().setFont(1, header_font)
        
        # Improved styling with better spacing
        self.packet_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #ffffff;
                alternate-background-color: #f9f9f9;
                border: none;
            }
            QTreeWidget::item {
                padding: 4px 0;
                min-height: 24px;
            }
            QTreeWidget::item:selected {
                background-color: #2196F3;
                color: white;
            }
            QHeaderView::section {
                background-color: #f0f0f0;
                padding: 10px 5px;
                border: none;
                border-bottom: 1px solid #d0d0d0;
                font-weight: bold;
                font-size: 12pt;
            }
        """)
        self.packet_tree.setColumnWidth(0, 350)  # Wider field column for better readability
        
        # Hex view with better styling and larger fonts
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        
        # Use monospace font with larger size
        if hasattr(self, 'mono_font'):
            self.hex_view.setFont(self.mono_font)
        else:
            self.hex_view.setFont(QFont("Courier New", 12))
            
        self.hex_view.setStyleSheet("""
            QTextEdit {
                background-color: #ffffff;
                border: none;
                padding: 10px;
                line-height: 1.6;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12pt;
            }
        """)
        
        # Raw data view with better styling and larger fonts
        self.raw_view = QTextEdit()
        self.raw_view.setReadOnly(True)
        
        # Use monospace font with larger size
        if hasattr(self, 'mono_font'):
            self.raw_view.setFont(self.mono_font)
        else:
            self.raw_view.setFont(QFont("Courier New", 12))
            
        self.raw_view.setStyleSheet("""
            QTextEdit {
                background-color: #ffffff;
                border: none;
                padding: 10px;
                line-height: 1.6;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12pt;
            }
        """)
        
        # Add summary tab
        self.summary_view = QTextEdit()
        self.summary_view.setReadOnly(True)
        self.summary_view.setStyleSheet("""
            QTextEdit {
                background-color: #f8f8f8;
                font-family: 'Segoe UI', 'Arial', sans-serif;
                line-height: 1.5;
            }
        """)
        
        # Create separate widgets for each view instead of tabs
        # This allows users to see multiple views simultaneously
        
        # Add packet tree to horizontal splitter
        self.horizontal_details_splitter.addWidget(self.packet_tree)
        
        # Create a second tab widget for the other views
        self.secondary_tabs = QTabWidget()
        self.secondary_tabs.setStyleSheet(self.details_tabs.styleSheet())
        self.secondary_tabs.addTab(self.hex_view, "Hex View")
        self.secondary_tabs.addTab(self.raw_view, "Raw Data")
        self.secondary_tabs.addTab(self.summary_view, "Summary")
        
        # Create database status tab
        self.db_status_view = QTextEdit()
        self.db_status_view.setReadOnly(True)
        
        # Use a larger font
        db_status_font = QFont(QApplication.font().family(), 12)
        self.db_status_view.setFont(db_status_font)
        
        self.db_status_view.setStyleSheet("""
            QTextEdit {
                background-color: #ffffff;
                border: none;
                padding: 10px;
                line-height: 1.6;
                font-family: 'Segoe UI', 'Arial', sans-serif;
                font-size: 12pt;
            }
        """)
        
        # Add database status tab
        self.secondary_tabs.addTab(self.db_status_view, "Database Status")
        
        # Set initial database status message
        self.db_status_view.setHtml("""
        <h2>Database Status</h2>
        <p>Loading database information...</p>
        <p>The desktop application does not directly store data in the database.</p>
        <p>To store captured data in PostgreSQL, use the main PyGuard application.</p>
        """)
        
        # Add secondary tabs to horizontal splitter
        self.horizontal_details_splitter.addWidget(self.secondary_tabs)
        
        # Connect tab change signal to update database status when tab is selected
        self.secondary_tabs.currentChanged.connect(self.on_tab_changed)
        
        # Set initial sizes for horizontal splitter
        self.horizontal_details_splitter.setSizes([400, 400])
        
        # Add the horizontal splitter to the details tabs
        self.details_tabs.addTab(self.horizontal_details_splitter, "Packet Analysis")
        
        # Create advanced filter tab
        self.advanced_filter_widget = QWidget()
        advanced_filter_layout = QVBoxLayout(self.advanced_filter_widget)
        advanced_filter_layout.setContentsMargins(10, 10, 10, 10)
        
        # Add search controls
        search_layout = QHBoxLayout()
        
        # Add search label
        search_label = QLabel("Advanced Query:")
        search_label.setStyleSheet("font-weight: bold;")
        search_layout.addWidget(search_label)
        
        # Add search input
        self.advanced_filter_input = QLineEdit()
        self.advanced_filter_input.setPlaceholderText("Enter query (e.g., src_ip=='192.168.1.1' and dst_port==80)")
        self.advanced_filter_input.returnPressed.connect(self.apply_advanced_filter)
        search_layout.addWidget(self.advanced_filter_input, 1)
        
        # Add search button
        search_button = QPushButton("Search")
        search_button.clicked.connect(self.apply_advanced_filter)
        search_layout.addWidget(search_button)
        
        # Add help button
        help_button = QPushButton("?")
        help_button.setToolTip("Show advanced query help")
        help_button.setFixedWidth(30)
        help_button.clicked.connect(self.show_advanced_filter_help)
        search_layout.addWidget(help_button)
        
        # Add clear button
        clear_button = QPushButton("Clear")
        clear_button.clicked.connect(self.clear_advanced_filter)
        search_layout.addWidget(clear_button)
        
        advanced_filter_layout.addLayout(search_layout)
        
        # Add results table
        self.advanced_filter_table = QTableWidget()
        self.advanced_filter_table.setColumnCount(7)
        self.advanced_filter_table.setHorizontalHeaderLabels(["#", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
        self.advanced_filter_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.advanced_filter_table.horizontalHeader().setStretchLastSection(True)
        self.advanced_filter_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.advanced_filter_table.setSelectionMode(QTableWidget.SingleSelection)
        self.advanced_filter_table.setAlternatingRowColors(True)
        self.advanced_filter_table.setSortingEnabled(True)
        self.advanced_filter_table.itemSelectionChanged.connect(self.on_advanced_filter_selection)
        
        # Set column widths
        self.advanced_filter_table.setColumnWidth(0, 60)  # #
        self.advanced_filter_table.setColumnWidth(1, 150)  # Time
        self.advanced_filter_table.setColumnWidth(2, 180)  # Source
        self.advanced_filter_table.setColumnWidth(3, 180)  # Destination
        self.advanced_filter_table.setColumnWidth(4, 80)   # Protocol
        self.advanced_filter_table.setColumnWidth(5, 80)   # Length
        
        advanced_filter_layout.addWidget(self.advanced_filter_table, 1)
        
        # Add status label
        self.advanced_filter_status = QLabel("No query applied. Showing all packets.")
        self.advanced_filter_status.setStyleSheet("color: #666; padding: 5px;")
        advanced_filter_layout.addWidget(self.advanced_filter_status)
        
        # Add advanced filter tab to details tabs
        self.details_tabs.addTab(self.advanced_filter_widget, "Advanced Filter")

        # IDS analysis tab
        self.ids_analysis_widget = IDSAnalysisWidget(self)  # Pass self as parent to prevent garbage collection
        self.ids_analysis_widget.analysisRequested.connect(self.analyze_with_ids)
        self.ids_analysis_widget.serviceCheckRequested.connect(self.check_ids_service_status)
        self.ids_analysis_widget.exportRequested.connect(self.export_ids_results)
        self.ids_analysis_widget.clearRequested.connect(self.clear_ids_results)
        self.details_tabs.addTab(self.ids_analysis_widget, "IDS Analysis")

        if not self.ids_backend_available or not self.ids_service_manager:
            self.ids_analysis_widget.set_error_state(
                "IDS analysis is unavailable. Install the 'requests' package or ensure the Final_IDS models are present."
            )
            self.ids_analysis_widget.analyze_btn.setEnabled(False)
        elif not self.ids_service_manager.has_remote_backend and self.ids_service_manager.supports_local_analysis:
            self.ids_analysis_widget.set_info_state(
                "Remote IDS service is unavailable. The built-in Final_IDS ML pipeline will run locally."
            )
        
        # ML Analysis tab removed
        
        # Create details splitter - fully resizable
        self.details_splitter = QSplitter(self)
        self.details_splitter.setOrientation(1)  # Vertical orientation
        self.details_splitter.setChildrenCollapsible(False)  # Prevent sections from being collapsed completely
        self.details_splitter.setHandleWidth(8)  # Wider handle for easier grabbing
        self.details_splitter.setOpaqueResize(True)  # Resize content during dragging for better feedback
        self.details_splitter.addWidget(self.details_tabs)
        
        # Connect tab change signal
        self.details_tabs.currentChanged.connect(self.on_details_tab_changed)
        
        # Add log view - now fully resizable
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(40)  # Minimum height to ensure visibility
        self.details_splitter.addWidget(self.log_view)
        
        # Add widgets to main splitter
        self.main_splitter.addWidget(self.packet_table)
        self.main_splitter.addWidget(self.details_splitter)
        
        # Load saved splitter states or use defaults
        self.load_ui_state()
        
        main_layout.addWidget(self.main_splitter, 1)  # Give splitter extra space
        
        # Create status bar with statistics and better styling
        self.statusBar().showMessage("Ready")
        self.statusBar().setStyleSheet("""
            QStatusBar {
                background-color: #f0f0f0;
                border-top: 1px solid #c0c0c0;
            }
            QLabel {
                padding: 3px 5px;
                border-right: 1px solid #c0c0c0;
            }
        """)
        
        # Add status widgets with better styling
        status_frame = QFrame()
        status_frame.setFrameShape(QFrame.NoFrame)
        status_layout = QHBoxLayout(status_frame)
        status_layout.setContentsMargins(0, 0, 0, 0)
        status_layout.setSpacing(0)
        
        # Status label
        self.status_label = QLabel("Stopped")
        self.status_label.setStyleSheet("color: #d32f2f; font-weight: bold;")  # Red for stopped
        self.status_label.setMinimumWidth(80)
        status_layout.addWidget(self.status_label)
        
        # Packets label
        self.packets_label = QLabel("Packets: 0")
        self.packets_label.setMinimumWidth(100)
        status_layout.addWidget(self.packets_label)
        
        # Rate label
        self.rate_label = QLabel("Rate: 0/s")
        self.rate_label.setMinimumWidth(80)
        status_layout.addWidget(self.rate_label)
        
        # Bytes label
        self.bytes_label = QLabel("Bytes: 0")
        self.bytes_label.setMinimumWidth(100)
        status_layout.addWidget(self.bytes_label)
        
        # Protocol counters
        self.tcp_label = QLabel("TCP: 0")
        self.tcp_label.setMinimumWidth(70)
        status_layout.addWidget(self.tcp_label)
        
        self.udp_label = QLabel("UDP: 0")
        self.udp_label.setMinimumWidth(70)
        status_layout.addWidget(self.udp_label)
        
        self.icmp_label = QLabel("ICMP: 0")
        self.icmp_label.setMinimumWidth(70)
        status_layout.addWidget(self.icmp_label)
        
        self.other_label = QLabel("Other: 0")
        self.other_label.setMinimumWidth(70)
        status_layout.addWidget(self.other_label)
        
        # Add progress bar for packet processing
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximumWidth(150)
        self.progress_bar.setVisible(False)
        self.progress_bar.setToolTip("Packet processing progress")
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #c0c0c0;
                border-radius: 3px;
                text-align: center;
                background-color: #f0f0f0;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                width: 10px;
            }
        """)
        status_layout.addWidget(self.progress_bar)
        
        # Add the status frame to the status bar
        self.statusBar().addPermanentWidget(status_frame)
        
        # Create timer for updating UI
        self.ui_timer = QTimer()
        self.ui_timer.timeout.connect(self.update_ui)
        self.ui_timer.start(1000)  # Update every second
        
        # Create timer for processing packet queue
        self.process_timer = QTimer()
        self.process_timer.timeout.connect(self.process_packet_queue)
        self.process_timer.start(self.display_update_interval)
        
        # Create progress bar for packet processing
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        self.statusBar().addPermanentWidget(self.progress_bar)
        
        # Setup log handler to display logs in the UI
        self.log_handler = LogHandler(self.log_view)
        logger.addHandler(self.log_handler)
        
        # Log startup message
        logger.info("PyGuard Desktop Application started - Wireshark-like UI with heavy traffic support")
    
    def check_interface_traffic(self, interface, timeout=1):
        """Check if an interface has active traffic
        
        Args:
            interface: Interface name to check
            timeout: Time in seconds to sniff for traffic
            
        Returns:
            bool: True if traffic was detected, False otherwise
        """
        try:
            from scapy.all import sniff
            
            # Create a packet counter
            packet_count = [0]
            
            # Define a callback that just counts packets
            def packet_callback(pkt):
                packet_count[0] += 1
                # Stop after first packet
                return True
            
            # Try to sniff for a short time to see if there's any traffic
            logger.debug(f"Checking for traffic on {interface}...")
            sniff(iface=interface, prn=packet_callback, timeout=timeout, store=0, count=1)
            
            # Return True if we captured any packets
            has_traffic = packet_count[0] > 0
            logger.debug(f"Interface {interface}: {'Traffic detected' if has_traffic else 'No traffic'}")
            return has_traffic
            
        except Exception as e:
            logger.debug(f"Error checking traffic on {interface}: {e}")
            # If there's an error, assume no traffic
            return False
    
    def get_interface_list(self):
        """Get a list of all network interfaces
        
        Returns:
            list: List of tuples (interface_name, display_name)
        """
        try:
            # Use scapy to get actual network interfaces
            from scapy.all import get_if_list, get_if_addr
            
            # Get list of interfaces
            all_interfaces = []
            
            try:
                # Try to get interfaces from scapy
                if_list = get_if_list()
                
                # Create a list of interfaces with their IP addresses
                for iface in if_list:
                    try:
                        # Try to get IP address
                        ip = get_if_addr(iface)
                        if ip:
                            # Add interface with IP address
                            interface_name = f"{iface} ({ip})"
                        else:
                            # Add interface without IP
                            interface_name = iface
                        
                        all_interfaces.append((iface, interface_name))
                    except:
                        # If we can't get IP, just add the interface name
                        all_interfaces.append((iface, iface))
                
            except Exception as e:
                logger.warning(f"Could not get interfaces from scapy: {e}")
                
                # Fall back to common interface names
                if sys.platform == 'win32':
                    # Common Windows interface names
                    common_interfaces = [
                        "Ethernet", "Wi-Fi", "Local Area Connection", 
                        "Wireless Network Connection", "eth0", "wlan0"
                    ]
                    
                    # Add some numbered interfaces that might exist
                    for i in range(5):
                        common_interfaces.append(f"Ethernet {i}")
                        common_interfaces.append(f"Wi-Fi {i}")
                    
                    all_interfaces = [(iface, iface) for iface in common_interfaces]
                else:
                    # Common Linux/macOS interface names
                    common_interfaces = ["eth0", "eth1", "wlan0", "wlan1", "en0", "en1", "lo"]
                    all_interfaces = [(iface, iface) for iface in common_interfaces]
            
            return all_interfaces
            
        except Exception as e:
            logger.error(f"Error getting interface list: {e}")
            return []
    
    def populate_all_interfaces(self):
        """Populate the interface combo box with all network interfaces (without traffic check)"""
        self.interface_combo.clear()
        
        try:
            # Get all interfaces
            all_interfaces = self.get_interface_list()
            
            # Add interfaces to combo box
            for _, display_name in all_interfaces:
                self.interface_combo.addItem(display_name)
            
            # Add option to manually enter interface name
            self.interface_combo.addItem("-- Enter manually --")
            
            # Add option to show only active interfaces
            self.interface_combo.addItem("-- Show only active interfaces --")
            
            logger.info(f"Added {len(all_interfaces)} total interface options")
        
        except Exception as e:
            logger.error(f"Error populating all interfaces: {e}")
            self.statusBar().showMessage(f"Error: {e}")
    
    def populate_interfaces(self):
        """Populate the interface combo box with network interfaces that have traffic"""
        self.interface_combo.clear()
        
        try:
            # Get all interfaces
            all_interfaces = self.get_interface_list()
            active_interfaces = []
            
            # Show a progress dialog while checking interfaces
            progress = QProgressDialog("Checking network interfaces for traffic...", "Cancel", 0, len(all_interfaces), self)
            progress.setWindowTitle("Interface Detection")
            progress.setWindowModality(Qt.WindowModal)
            progress.setMinimumDuration(500)  # Only show for operations taking > 500ms
            progress.setValue(0)
            
            # Check each interface for traffic
            for i, (iface, display_name) in enumerate(all_interfaces):
                # Update progress
                progress.setValue(i)
                QApplication.processEvents()
                
                # Check for user cancel
                if progress.wasCanceled():
                    break
                
                # Check if this interface has traffic
                if self.check_interface_traffic(iface):
                    active_interfaces.append(display_name)
                    logger.info(f"Found active interface: {display_name}")
            
            # Close progress dialog
            progress.setValue(len(all_interfaces))
            
            # If no active interfaces were found, fall back to showing all interfaces
            if not active_interfaces:
                logger.info("No active interfaces found, showing all interfaces")
                active_interfaces = [display_name for _, display_name in all_interfaces]
            
            # Add interfaces to combo box
            for interface in active_interfaces:
                self.interface_combo.addItem(interface)
            
            # Add option to manually enter interface name
            self.interface_combo.addItem("-- Enter manually --")
            
            # Add option to show all interfaces
            self.interface_combo.addItem("-- Show all interfaces --")
            
            # Connect to the combo box change event
            self.interface_combo.currentTextChanged.connect(self.on_interface_changed)
            
            logger.info(f"Added {len(active_interfaces)} active interface options")
        
        except Exception as e:
            logger.error(f"Error populating interfaces: {e}")
            self.statusBar().showMessage(f"Error: {e}")
    
    def on_interface_changed(self, text):
        """Handle interface selection change"""
        if text == "-- Enter manually --":
            # Prompt user to enter interface name
            interface_name, ok = QInputDialog.getText(
                self, "Enter Interface Name", 
                "Enter the exact network interface name:"
            )
            if ok and interface_name:
                # Add the custom interface to the combo box
                self.interface_combo.insertItem(0, interface_name)
                self.interface_combo.setCurrentIndex(0)
            else:
                # User canceled, revert to first item
                self.interface_combo.setCurrentIndex(0)
        elif text == "-- Show all interfaces --":
            # Disconnect the signal to prevent recursion
            self.interface_combo.currentTextChanged.disconnect(self.on_interface_changed)
            
            # Show a progress dialog
            progress = QProgressDialog("Loading all interfaces...", "Cancel", 0, 100, self)
            progress.setWindowTitle("Interface Detection")
            progress.setWindowModality(Qt.WindowModal)
            progress.setMinimumDuration(500)
            progress.setValue(10)
            QApplication.processEvents()
            
            # Repopulate with all interfaces (without traffic check)
            self.populate_all_interfaces()
            
            # Close progress dialog
            progress.setValue(100)
            
            # Reconnect the signal
            self.interface_combo.currentTextChanged.connect(self.on_interface_changed)
            
            # Select the first interface
            if self.interface_combo.count() > 0:
                self.interface_combo.setCurrentIndex(0)
        elif text == "-- Show only active interfaces --":
            # Disconnect the signal to prevent recursion
            self.interface_combo.currentTextChanged.disconnect(self.on_interface_changed)
            
            # Show a progress dialog
            progress = QProgressDialog("Detecting active interfaces...", "Cancel", 0, 100, self)
            progress.setWindowTitle("Interface Detection")
            progress.setWindowModality(Qt.WindowModal)
            progress.setMinimumDuration(500)
            progress.setValue(10)
            QApplication.processEvents()
            
            # Repopulate with only active interfaces
            self.populate_interfaces()
            
            # Close progress dialog
            progress.setValue(100)
            
            # Reconnect the signal
            self.interface_combo.currentTextChanged.connect(self.on_interface_changed)
            
            # Select the first interface
            if self.interface_combo.count() > 0:
                self.interface_combo.setCurrentIndex(0)
        else:
            # If the interface name contains an IP address in parentheses, extract just the interface name
            if " (" in text and ")" in text:
                # Extract the interface name (everything before the space and opening parenthesis)
                self.selected_interface = text.split(" (")[0]
            else:
                self.selected_interface = text
    
    def start_capture(self):
        """Start packet capture"""
        try:
            # Get selected interface
            if self.selected_interface:
                interface = self.selected_interface
            else:
                interface_text = self.interface_combo.currentText()
                # If the interface name contains an IP address in parentheses, extract just the interface name
                if " (" in interface_text and ")" in interface_text:
                    # Extract the interface name (everything before the space and opening parenthesis)
                    interface = interface_text.split(" (")[0]
                else:
                    interface = interface_text
                self.selected_interface = interface
            
            # Get filter expression
            filter_expression = self.filter_text.text().strip()
            
            # Create and start capture thread
            self.capture_thread = PacketCapture(interface, filter_expression)
            self.capture_thread.packet_captured.connect(self.queue_packet)
            self.capture_thread.status_update.connect(self.update_status)
            self.capture_thread.error_occurred.connect(self.handle_error)
            self.capture_thread.start()
            
            # Update UI
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.status_label.setText("Running")
            self.status_label.setStyleSheet("color: #388e3c; font-weight: bold;")  # Green for running
            self.statusBar().showMessage("Capture started")
            
            # Clear packet display
            self.packet_table.setRowCount(0)
            self.packet_tree.clear()
            self.hex_view.clear()
            self.raw_view.clear()
            self.summary_view.clear()
            self.advanced_filter_table.setRowCount(0)
            self.advanced_filter_status.setText("No packets captured yet.")
            self.captured_packets = []
            
            # Reset protocol statistics
            for key in self.protocol_stats:
                self.protocol_stats[key] = 0
                
            # Update status labels
            self.tcp_label.setText("TCP: 0")
            self.udp_label.setText("UDP: 0")
            self.icmp_label.setText("ICMP: 0")
            self.other_label.setText("Other: 0")
            
            # Reset packet queue
            while not self.packet_queue.empty():
                self.packet_queue.get()
            
            # Start processing
            self.is_processing = True
            
            # Start processing timer
            if hasattr(self, 'timer') and self.timer.isActive():
                self.timer.stop()
            
            self.timer = QTimer(self)
            self.timer.timeout.connect(self.process_packet_queue)
            self.timer.start(self.display_update_interval)
            
            # Initialize packet statistics
            self.last_packet_count = 0
            self.last_update_time = time.time()
            
            logger.info(f"Capture started on interface {interface} with filter: {filter_expression}")
        
        except Exception as e:
            logger.error(f"Error starting capture: {e}")
            self.statusBar().showMessage(f"Error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to start capture: {e}")
    
    def stop_capture(self):
        """Stop packet capture"""
        try:
            if self.capture_thread and self.capture_thread.isRunning():
                logger.info("Stopping packet capture...")
                
                # Update UI to show stopping state
                self.start_button.setEnabled(False)
                self.stop_button.setEnabled(False)
                self.status_label.setText("Stopping...")
                self.status_label.setStyleSheet("color: #ff9800; font-weight: bold;")  # Orange for stopping
                self.statusBar().showMessage("Stopping capture...")
                
                # Stop the capture thread
                self.capture_thread.stop()
                
                # Wait for thread to finish (with timeout)
                if not self.capture_thread.wait(3000):  # Wait up to 3 seconds
                    logger.warning("Thread did not stop gracefully, forcing termination")
                    self.capture_thread.terminate()
                    self.capture_thread.wait(1000)  # Wait for termination
                
                # Update UI to stopped state
                self.start_button.setEnabled(True)
                self.stop_button.setEnabled(False)
                self.status_label.setText("Stopped")
                self.status_label.setStyleSheet("color: #d32f2f; font-weight: bold;")  # Red for stopped
                self.statusBar().showMessage("Capture stopped")
                
                # Process any remaining packets
                self.process_packet_queue()
                
                # Stop the processing timer
                if hasattr(self, 'timer') and self.timer.isActive():
                    self.timer.stop()
                
                # Hide progress bar
                self.progress_bar.setVisible(False)
                
                logger.info("Capture stopped successfully")
            else:
                logger.info("No capture thread running")
                # Update UI to stopped state anyway
                self.start_button.setEnabled(True)
                self.stop_button.setEnabled(False)
                self.status_label.setText("Stopped")
                self.status_label.setStyleSheet("color: #d32f2f; font-weight: bold;")
                self.statusBar().showMessage("No capture running")
        
        except Exception as e:
            logger.error(f"Error stopping capture: {e}")
            self.statusBar().showMessage(f"Error stopping capture: {e}")
            
            # Reset UI state even if there was an error
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.status_label.setText("Error")
            self.status_label.setStyleSheet("color: #d32f2f; font-weight: bold;")
    
    def restart_capture(self):
        """Restart packet capture"""
        try:
            # Stop current capture if running
            if self.capture_thread and self.capture_thread.isRunning():
                self.stop_capture()
            
            # Clear display
            reply = QMessageBox.question(
                self, "Restart Capture",
                "Do you want to clear the current packets before restarting?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
            )
            
            if reply == QMessageBox.Yes:
                self.clear_display()
            
            # Start new capture
            self.start_capture()
            
            logger.info("Capture restarted")
        
        except Exception as e:
            logger.error(f"Error restarting capture: {e}")
            self.statusBar().showMessage(f"Error: {e}")

    # ------------------------------------------------------------------ #
    # IDS integration
    # ------------------------------------------------------------------ #
    def analyze_with_ids(self):
        """Handle Analyze with IDS button click."""
        if not self.ids_service_manager:
            QMessageBox.warning(
                self,
                "IDS Analysis",
                "IDS integration is not initialized. Please restart the application after ensuring dependencies are installed.",
            )
            return

        if not self.ids_service_manager.has_any_backend:
            QMessageBox.warning(
                self,
                "IDS Analysis",
                "IDS analysis is unavailable. Install the 'requests' package or ensure the Final_IDS models are present.",
            )
            return

        if not self.captured_packets:
            QMessageBox.information(
                self,
                "IDS Analysis",
                "No captured packets are available for analysis.",
            )
            return

        if self.ids_analysis_worker and self.ids_analysis_worker.isRunning():
            QMessageBox.information(
                self,
                "IDS Analysis",
                "An IDS analysis is already in progress.",
            )
            return

        healthy = self.ids_service_manager.check_health()
        if not healthy:
            message = self.ids_service_manager.last_error or "Unable to reach the IDS backend."
            if self.ids_service_manager.has_remote_backend:
                response = QMessageBox.question(
                    self,
                    "IDS Service Not Reachable",
                    f"{message}\n\nDo you want to attempt the analysis anyway?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                )
                if response != QMessageBox.Yes:
                    return
            else:
                QMessageBox.warning(self, "IDS Analysis", message)
                return

        try:
            self._cleanup_ids_temp_file()
            self.ids_temp_pcap_path = self._create_ids_temp_pcap()
        except Exception as exc:
            logger.error("Failed to prepare PCAP for IDS analysis: %s", exc)
            QMessageBox.critical(self, "IDS Analysis", f"Failed to prepare capture for IDS: {exc}")
            return

        if self.ids_analysis_widget:
            self.ids_analysis_widget.set_busy_state("Submitting capture to IDS...")

        self._set_ids_actions_enabled(False)

        self.ids_progress_dialog = QProgressDialog("Submitting capture to IDS...", None, 0, 0, self)
        self.ids_progress_dialog.setWindowTitle("IDS Analysis")
        self.ids_progress_dialog.setWindowModality(Qt.WindowModal)
        self.ids_progress_dialog.setCancelButton(None)
        self.ids_progress_dialog.setMinimumDuration(0)
        self.ids_progress_dialog.show()

        worker = IDSAnalysisWorker(self.ids_service_manager, self.ids_temp_pcap_path)
        worker.finished.connect(self.on_ids_analysis_complete)
        worker.error.connect(self.on_ids_analysis_error)
        worker.finished.connect(worker.deleteLater)
        worker.error.connect(worker.deleteLater)
        self.ids_analysis_worker = worker
        worker.start()

    def check_ids_service_status(self):
        """Verify IDS service is running."""
        if not self.ids_service_manager:
            QMessageBox.warning(
                self,
                "IDS Service",
                "IDS integration is not initialized. Please restart the application after ensuring dependencies are installed.",
            )
            return

        if not self.ids_service_manager.has_any_backend:
            QMessageBox.warning(
                self,
                "IDS Service",
                "IDS analysis is unavailable. Install the 'requests' package or ensure the Final_IDS models are present.",
            )
            return

        if self.ids_service_manager.check_health():
            backend = self.ids_service_manager.active_backend or "local"
            if backend == "remote":
                message = "Remote IDS service is reachable and healthy."
            else:
                message = "Local Final_IDS ML pipeline is ready to analyze captures."
            QMessageBox.information(self, "IDS Service", message)
        else:
            message = self.ids_service_manager.last_error or "Unable to reach the IDS backend."
            QMessageBox.warning(self, "IDS Service", message)

    def on_ids_analysis_complete(self, results: Dict) -> None:
        """Handle completion of the IDS analysis worker."""
        logger.info("IDS analysis completed successfully.")
        logger.debug(f"Raw results keys: {list(results.keys()) if isinstance(results, dict) else 'Not a dict'}")
        self._cleanup_ids_temp_file()
        self._set_ids_actions_enabled(True)

        if self.ids_progress_dialog:
            self.ids_progress_dialog.close()
            self.ids_progress_dialog = None

        self.ids_analysis_worker = None

        if self.ids_service_manager:
            prepared = self.ids_service_manager.prepare_results_payload(results)
            logger.debug(f"Prepared payload keys: {list(prepared.keys())}")
            logger.debug(f"Summary keys: {list(prepared.get('summary', {}).keys())}")
            logger.debug(f"Total flows: {prepared.get('summary', {}).get('total_flows', 'N/A')}")
        else:
            prepared = {"raw": results, "summary": {}}
        self.ids_last_results = prepared

        # Ensure widget exists before displaying results
        if self.ids_analysis_widget is None:
            logger.warning("ids_analysis_widget is None - recreating widget...")
            try:
                self.ids_analysis_widget = IDSAnalysisWidget(self)
                self.ids_analysis_widget.analysisRequested.connect(self.analyze_with_ids)
                self.ids_analysis_widget.serviceCheckRequested.connect(self.check_ids_service_status)
                self.ids_analysis_widget.exportRequested.connect(self.export_ids_results)
                self.ids_analysis_widget.clearRequested.connect(self.clear_ids_results)
                # Re-add to tabs if not already there
                tab_index = self.details_tabs.indexOf(self.ids_analysis_widget)
                if tab_index == -1:
                    self.details_tabs.addTab(self.ids_analysis_widget, "IDS Analysis")
                logger.info("IDS analysis widget recreated successfully.")
            except Exception as exc:
                logger.error("Failed to recreate IDS analysis widget: %s", exc)
                return
        
        # Display results in the widget
        try:
            logger.debug("Calling ids_analysis_widget.display_results...")
            self.ids_analysis_widget.display_results(prepared)
            # Force UI refresh
            self.ids_analysis_widget.update()
            self.ids_analysis_widget.repaint()
            # Switch to IDS Analysis tab to show results
            self.details_tabs.setCurrentWidget(self.ids_analysis_widget)
            logger.debug("IDS analysis widget updated, UI refreshed, and tab switched.")
        except Exception as exc:
            logger.error("Failed to display IDS results: %s", exc)

        backend_label = "local Final_IDS pipeline"
        if self.ids_service_manager and self.ids_service_manager.active_backend != "local":
            backend_label = "IDS service"
        self.statusBar().showMessage(f"IDS analysis complete via {backend_label}.", 5000)

    def on_ids_analysis_error(self, message: str) -> None:
        """Handle errors from the IDS analysis worker."""
        logger.error("IDS analysis failed: %s", message)
        self._cleanup_ids_temp_file()
        self._set_ids_actions_enabled(True)

        if self.ids_progress_dialog:
            self.ids_progress_dialog.close()
            self.ids_progress_dialog = None

        if self.ids_analysis_widget:
            self.ids_analysis_widget.set_error_state(f"IDS analysis failed: {message}")

        QMessageBox.critical(self, "IDS Analysis", f"IDS analysis failed:\n{message}")
        self.ids_analysis_worker = None

    def export_ids_results(self) -> None:
        """Export IDS results to a CSV file."""
        if not self.ids_last_results:
            QMessageBox.information(self, "Export IDS Results", "No IDS results are available to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export IDS Results",
            "ids_analysis_results.csv",
            "CSV Files (*.csv);;All Files (*.*)",
        )
        if not file_path:
            return

        summary = self.ids_last_results.get("summary") or {}
        detailed = summary.get("detailed_results") or []

        try:
            with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)

                writer.writerow(["Metric", "Value"])
                writer.writerow(["Total Flows", summary.get("total_flows", 0)])
                writer.writerow(["Attack Flows", summary.get("attack_flows", 0)])
                writer.writerow(["Benign Flows", summary.get("benign_flows", 0)])
                writer.writerow(["Average Confidence", f"{summary.get('average_confidence', 0.0):.4f}"])

                writer.writerow([])
                writer.writerow(["Attack Type", "Flow Count"])
                for label, count in (summary.get("attack_summary") or {}).items():
                    writer.writerow([label, count])

                writer.writerow([])
                writer.writerow(["Flow ID", "Source IP", "Destination IP", "Predicted Label", "Confidence"])
                for index, record in enumerate(detailed[:100], start=1):
                    flow_id = record.get("flow_id") or record.get("Flow ID") or index
                    src_ip = record.get("src_ip") or record.get("Source IP") or record.get("Src IP") or ""
                    dst_ip = record.get("dst_ip") or record.get("Destination IP") or record.get("Dest IP") or ""
                    label = record.get("Predicted_Label") or record.get("label") or record.get("Label") or ""
                    confidence = record.get("Confidence", "")

                    writer.writerow(
                        [
                            clean_unicode_for_csv(flow_id),
                            clean_unicode_for_csv(src_ip),
                            clean_unicode_for_csv(dst_ip),
                            clean_unicode_for_csv(label),
                            clean_unicode_for_csv(confidence),
                        ]
                    )
        except OSError as exc:
            logger.error("Failed to export IDS results: %s", exc)
            QMessageBox.critical(self, "Export IDS Results", f"Failed to export IDS results:\n{exc}")
            return

        self.statusBar().showMessage(f"IDS results exported to {file_path}", 5000)

    def clear_ids_results(self) -> None:
        """Clear cached IDS results when the widget is reset."""
        self.ids_last_results = None

    def _set_ids_actions_enabled(self, enabled: bool) -> None:
        """Enable or disable IDS-related actions in the UI."""
        if not self.ids_service_manager:
            allow = False
        else:
            allow = enabled and self.ids_service_manager.has_any_backend
        if hasattr(self, "analyze_ids_action") and self.analyze_ids_action:
            self.analyze_ids_action.setEnabled(allow)
        if self.ids_analysis_widget:
            self.ids_analysis_widget.analyze_btn.setEnabled(allow)

    def _create_ids_temp_pcap(self) -> str:
        """Create a temporary PCAP file from the captured packets."""
        if not self.captured_packets:
            raise ValueError("No packets available to export.")

        fd, path = tempfile.mkstemp(prefix="pyguard_ids_", suffix=".pcap")
        os.close(fd)

        written = self._write_packets_to_pcap(self.captured_packets, path)
        if written == 0:
            os.remove(path)
            raise ValueError("No packets contained raw data suitable for PCAP export.")

        return path

    def _write_packets_to_pcap(self, packets: List[Dict], destination: str) -> int:
        """Write captured packets to a PCAP file."""
        written = 0
        with open(destination, "wb") as handle:
            handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for packet in packets:
                packet_data = packet.get("packet_data")
                if not packet_data:
                    continue

                ts_sec, ts_usec = self._parse_packet_timestamp(packet.get("timestamp"))
                incl_len = len(packet_data)
                handle.write(struct.pack("<IIII", ts_sec, ts_usec, incl_len, incl_len))
                handle.write(packet_data)
                written += 1
        return written

    def _write_packets_to_csv(self, packets: List[Dict], destination: str) -> int:
        """Write captured packets to a CSV file."""
        fieldnames = [
            "frame_number",
            "timestamp",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "protocol",
            "size",
            "summary",
        ]

        written = 0
        with open(destination, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for packet in packets:
                row = {
                    "frame_number": packet.get("frame_number", written + 1),
                    "timestamp": packet.get("timestamp", ""),
                    "src_ip": packet.get("src_ip", ""),
                    "src_port": packet.get("src_port", ""),
                    "dst_ip": packet.get("dst_ip", ""),
                    "dst_port": packet.get("dst_port", ""),
                    "protocol": packet.get("protocol", ""),
                    "size": packet.get("size", 0),
                    "summary": packet.get("summary", ""),
                }
                writer.writerow({k: clean_unicode_for_csv(v) for k, v in row.items()})
                written += 1

        return written

    def _parse_packet_timestamp(self, timestamp: Optional[str]) -> Tuple[int, int]:
        """Convert packet timestamp string to epoch seconds and microseconds."""
        if not timestamp:
            now = time.time()
            sec = int(now)
            usec = int((now - sec) * 1_000_000)
            return sec, usec

        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(timestamp, fmt)
                return int(dt.timestamp()), dt.microsecond
            except ValueError:
                continue

        now = time.time()
        sec = int(now)
        usec = int((now - sec) * 1_000_000)
        return sec, usec

    def _cleanup_ids_temp_file(self) -> None:
        """Remove any temporary PCAP file generated for IDS analysis."""
        if self.ids_temp_pcap_path and os.path.exists(self.ids_temp_pcap_path):
            try:
                os.remove(self.ids_temp_pcap_path)
            except OSError as exc:
                logger.warning("Failed to remove temporary IDS PCAP file %s: %s", self.ids_temp_pcap_path, exc)
        self.ids_temp_pcap_path = None
    
    def queue_packet(self, metadata):
        """Add packet to processing queue"""
        if metadata:
            try:
                self.packet_queue.put(metadata)
            except queue.Full:
                logger.warning("Packet queue full, dropping packet")
    
    def process_packet_queue(self):
        """Process packets from the queue in batches"""
        if not self.is_processing:
            return
        
        # Show progress bar if queue has many packets
        queue_size = self.packet_queue.qsize()
        if queue_size > self.packet_buffer_size:
            self.progress_bar.setVisible(True)
            progress_percent = min(100, int(self.packet_buffer_size * 100 / queue_size))
            self.progress_bar.setValue(progress_percent)
            self.progress_bar.setFormat(f"{progress_percent}% ({queue_size:,} packets in queue)")
        else:
            self.progress_bar.setVisible(False)
        
        # Process a batch of packets
        packets_to_process = min(queue_size, self.packet_buffer_size)
        if packets_to_process == 0:
            return
        
        # Temporarily disable UI updates for better performance
        self.packet_table.setUpdatesEnabled(False)
        
        # Check if we need to limit displayed packets
        current_count = self.packet_table.rowCount()
        if current_count >= self.max_display_packets:
            # Calculate how many packets to remove
            to_remove = min(packets_to_process, current_count - self.max_display_packets + packets_to_process)
            
            if to_remove > 0:
                # Show progress dialog for large removals
                if to_remove > 1000:
                    progress = QProgressDialog("Removing old packets...", "Cancel", 0, to_remove, self)
                    progress.setWindowTitle("Packet Limit Reached")
                    progress.setWindowModality(Qt.WindowModal)
                    progress.setMinimumDuration(500)  # Only show for operations taking > 500ms
                    progress.setValue(0)
                
                # Update status bar
                self.statusBar().showMessage(
                    f"Removing {to_remove:,} oldest packets to stay within display limit of {self.max_display_packets:,}"
                )
                
                # Disable UI updates for better performance
                self.packet_table.setUpdatesEnabled(False)
                
                try:
                    # Remove packets in batches for better performance
                    batch_size = 100
                    for i in range(0, to_remove, batch_size):
                        # Calculate batch end
                        end = min(i + batch_size, to_remove)
                        batch_count = end - i
                        
                        # Remove rows in batch
                        for j in range(batch_count):
                            self.packet_table.removeRow(0)
                        
                        # Update progress for large removals
                        if to_remove > 1000:
                            progress.setValue(end)
                            QApplication.processEvents()
                            
                            # Check for cancel
                            if progress.wasCanceled():
                                break
                    
                    # Also remove from captured_packets list
                    if len(self.captured_packets) >= to_remove:
                        self.captured_packets = self.captured_packets[to_remove:]
                        
                        # Update frame numbers in remaining packets
                        for i, packet in enumerate(self.captured_packets):
                            packet["frame_number"] = i + 1
                    
                    # Force garbage collection to free memory
                    import gc
                    gc.collect()
                    
                finally:
                    # Always re-enable UI updates
                    self.packet_table.setUpdatesEnabled(True)
                    
                    # Close progress dialog if it was shown
                    if to_remove > 1000:
                        progress.close()
                    
                    # Update window title with new packet count
                    self.setWindowTitle(f"PyGuard Desktop - {len(self.captured_packets):,} packets captured")
        
        # Process packets
        processed_count = 0
        for _ in range(packets_to_process):
            try:
                metadata = self.packet_queue.get_nowait()
                self.handle_packet(metadata)
                self.packet_queue.task_done()
                processed_count += 1
            except queue.Empty:
                break
        
        # Re-enable UI updates
        self.packet_table.setUpdatesEnabled(True)
        
        # Update advanced filter table if the tab is visible and no filter is applied
        if self.details_tabs.currentWidget() == self.advanced_filter_widget and not self.advanced_filter_input.text().strip():
            # Only update if we're showing all packets (no filter applied)
            self.update_advanced_filter_table()
        
        # Update status bar with processing info if we processed a significant number of packets
        if processed_count > 100:
            self.statusBar().showMessage(f"Processed {processed_count:,} packets. {queue_size - processed_count:,} remaining in queue.")
            
        # Schedule next processing if there are still packets in the queue
        if not self.packet_queue.empty() and self.is_processing:
            QTimer.singleShot(10, self.process_packet_queue)
            
    def get_packet_color(self, packet):
        """Determine the background color for a packet based on its properties"""
        # Default color (white)
        color = QColor(255, 255, 255)
        
        # Get protocol information
        protocol = packet.get("protocol", "")
        layers = packet.get("layers", [])
        
        # Check for errors or warnings
        if packet.get("error", False):
            # Error packets - light red
            return QColor(255, 200, 200)
            
        # Color by protocol
        if "HTTP" in layers:
            # HTTP - light blue
            return QColor(210, 230, 255)
        elif "DNS" in layers:
            # DNS - light purple
            return QColor(230, 210, 255)
        elif "ICMP" in layers or protocol == "ICMP":
            # ICMP - light yellow
            return QColor(255, 255, 200)
        elif "ARP" in layers or protocol == "ARP":
            # ARP - light green
            return QColor(210, 255, 210)
        elif protocol == "TCP":
            # Check for specific TCP ports
            dst_port = packet.get("dst_port", 0)
            src_port = packet.get("src_port", 0)
            
            if dst_port == 80 or src_port == 80:
                # HTTP - light blue
                return QColor(210, 230, 255)
            elif dst_port == 443 or src_port == 443:
                # HTTPS - slightly darker blue
                return QColor(180, 210, 255)
            elif dst_port == 22 or src_port == 22:
                # SSH - light orange
                return QColor(255, 230, 200)
            elif dst_port == 21 or src_port == 21:
                # FTP - light pink
                return QColor(255, 200, 230)
            else:
                # Other TCP - very light blue
                return QColor(240, 248, 255)
        elif protocol == "UDP":
            # Check for specific UDP ports
            dst_port = packet.get("dst_port", 0)
            src_port = packet.get("src_port", 0)
            
            if dst_port == 53 or src_port == 53:
                # DNS - light purple
                return QColor(230, 210, 255)
            elif dst_port == 67 or dst_port == 68 or src_port == 67 or src_port == 68:
                # DHCP - light cyan
                return QColor(200, 255, 255)
            else:
                # Other UDP - very light green
                return QColor(240, 255, 240)
        
        # Default color for other protocols
        return color
    
    def update_advanced_filter_table(self):
        """Update the advanced filter table with the latest packets"""
        try:
            # Get current row count
            current_rows = self.advanced_filter_table.rowCount()
            
            # Get total packets
            total_packets = len(self.captured_packets)
            
            # If we have more packets than rows, add the new ones
            if total_packets > current_rows:
                # Set new row count
                self.advanced_filter_table.setRowCount(total_packets)
                
                # Add new packets
                for row in range(current_rows, total_packets):
                    packet = self.captured_packets[row]
                    
                    # Get color for this packet
                    bg_color = self.get_packet_color(packet)
                    
                    # Packet number
                    item = QTableWidgetItem(str(row + 1))
                    item.setData(Qt.UserRole, row)  # Store original index
                    item.setBackground(bg_color)
                    self.advanced_filter_table.setItem(row, 0, item)
                    
                    # Time
                    time_str = packet.get("timestamp", "")
                    if isinstance(time_str, str) and len(time_str) > 19:
                        time_str = time_str[:19]  # Truncate microseconds
                    item = QTableWidgetItem(time_str)
                    item.setBackground(bg_color)
                    self.advanced_filter_table.setItem(row, 1, item)
                    
                    # Source
                    src = packet.get("src_ip", "")
                    if "src_port" in packet and packet["src_port"]:
                        src += f":{packet['src_port']}"
                    item = QTableWidgetItem(src)
                    item.setBackground(bg_color)
                    self.advanced_filter_table.setItem(row, 2, item)
                    
                    # Destination
                    dst = packet.get("dst_ip", "")
                    if "dst_port" in packet and packet["dst_port"]:
                        dst += f":{packet['dst_port']}"
                    item = QTableWidgetItem(dst)
                    item.setBackground(bg_color)
                    self.advanced_filter_table.setItem(row, 3, item)
                    
                    # Protocol
                    protocol = packet.get("protocol", "")
                    if not protocol and "layers" in packet:
                        protocol = packet["layers"][-1] if packet["layers"] else ""
                    item = QTableWidgetItem(protocol)
                    item.setBackground(bg_color)
                    self.advanced_filter_table.setItem(row, 4, item)
                    
                    # Length
                    length = packet.get("size", 0)
                    item = QTableWidgetItem(str(length))
                    item.setBackground(bg_color)
                    self.advanced_filter_table.setItem(row, 5, item)
                    
                    # Info/Summary
                    summary = packet.get("summary", "")
                    item = QTableWidgetItem(summary)
                    item.setBackground(bg_color)
                    self.advanced_filter_table.setItem(row, 6, item)
                
                # Update status
                self.advanced_filter_status.setText(f"Showing all {total_packets} packets.")
        
        except Exception as e:
            logger.error(f"Error updating advanced filter table: {e}")
    
    def update_protocol_stats(self, packet: Dict[str, Any]) -> None:
        """Increment protocol counters and refresh their labels."""
        protocol = str(packet.get("protocol", "")).upper()
        layers = [
            str(layer).upper()
            for layer in packet.get("layers", [])
            if isinstance(layer, str)
        ]

        def bump(key: str) -> None:
            self.protocol_stats[key] = self.protocol_stats.get(key, 0) + 1

        matched = False
        if protocol == "TCP" or "TCP" in layers:
            bump("tcp_packets")
            matched = True
        elif protocol == "UDP" or "UDP" in layers:
            bump("udp_packets")
            matched = True
        elif protocol == "ICMP" or "ICMP" in layers:
            bump("icmp_packets")
            matched = True
        elif protocol == "ARP" or "ARP" in layers:
            bump("arp_packets")
            matched = True

        # Higher-layer protocols (count independently of transport)
        if protocol == "DNS" or "DNS" in layers or packet.get("dns"):
            bump("dns_packets")
        if protocol == "HTTP" or "HTTP" in layers or packet.get("http_data"):
            bump("http_packets")

        if not matched:
            bump("other_packets")

        # Update the labels so the UI reflects the latest totals immediately
        self.tcp_label.setText(f"TCP: {self.protocol_stats['tcp_packets']:,}")
        self.udp_label.setText(f"UDP: {self.protocol_stats['udp_packets']:,}")
        self.icmp_label.setText(f"ICMP: {self.protocol_stats['icmp_packets']:,}")
        self.other_label.setText(f"Other: {self.protocol_stats['other_packets']:,}")

    def update_status(self, stats: Dict[str, Any]) -> None:
        """Update capture statistics shown in the status widgets."""
        if self.capture_thread and self.capture_thread.isRunning():
            self.status_label.setText("Running")
            self.status_label.setStyleSheet("color: #388e3c; font-weight: bold;")
        else:
            self.status_label.setText("Stopped")
            self.status_label.setStyleSheet("color: #d32f2f; font-weight: bold;")

        packets_captured = stats.get("packets_captured", 0)
        self.packets_label.setText(f"Packets: {packets_captured:,}")

        bytes_captured = stats.get("bytes_captured", 0)
        if bytes_captured < 1024:
            self.bytes_label.setText(f"Bytes: {bytes_captured:,} B")
        elif bytes_captured < 1024 * 1024:
            self.bytes_label.setText(f"Bytes: {bytes_captured / 1024:.1f} KB")
        else:
            self.bytes_label.setText(f"Bytes: {bytes_captured / (1024 * 1024):.1f} MB")

        if stats.get("start_time"):
            elapsed = time.time() - stats["start_time"]
            if elapsed > 0:
                rate = stats.get("packets_captured", 0) / elapsed
                self.rate_label.setText(f"Rate: {rate:.1f}/s")

            elapsed_str = time.strftime("%H:%M:%S", time.gmtime(elapsed))
            status_msg = f"Running for {elapsed_str}"
            if hasattr(self, "last_packet_count") and hasattr(self, "last_update_time"):
                time_diff = time.time() - self.last_update_time
                if time_diff > 0:
                    recent_rate = (packets_captured - self.last_packet_count) / time_diff
                    status_msg = f"{status_msg} | Current rate: {recent_rate:.1f} packets/sec"
            self.last_packet_count = packets_captured
            self.last_update_time = time.time()
            self.statusBar().showMessage(status_msg)

    def handle_error(self, error_message: str) -> None:
        """Handle errors emitted from worker threads."""
        logger.error("Capture error: %s", error_message)
        self.status_label.setText("Error")
        self.status_label.setStyleSheet("color: #d32f2f; font-weight: bold;")
        self.statusBar().showMessage(f"Error: {error_message}")

        QMessageBox.critical(self, "Capture Error", f"Failed to capture packets:\n{error_message}")

        if self.capture_thread and self.capture_thread.isRunning():
            try:
                self.capture_thread.stop()
                if not self.capture_thread.wait(2000):
                    self.capture_thread.terminate()
                    self.capture_thread.wait(500)
            except Exception as exc:
                logger.exception("Failed to stop capture thread: %s", exc)

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)

    def handle_packet(self, metadata):
        """Handle a captured packet"""
        if metadata:
            # Add packet to list
            self.captured_packets.append(metadata)
            
            # Add frame number
            metadata["frame_number"] = len(self.captured_packets)
            
            # Update protocol statistics
            self.update_protocol_stats(metadata)
            
            # Add to packet table
            row = self.packet_table.rowCount()
            self.packet_table.insertRow(row)
            
            # Set packet number
            self.packet_table.setItem(row, 0, QTableWidgetItem(str(metadata["frame_number"])))
            
            # Set timestamp (just time part)
            timestamp = metadata.get("timestamp", "")
            if timestamp:
                try:
                    # Extract just the time part (HH:MM:SS.mmm)
                    time_part = timestamp.split(" ")[1].split(".")[0]
                    self.packet_table.setItem(row, 1, QTableWidgetItem(time_part))
                except:
                    self.packet_table.setItem(row, 1, QTableWidgetItem(timestamp))
            
            # Set source
            source = metadata.get("src_ip", "")
            if "src_port" in metadata and metadata["src_port"]:
                source += f":{metadata['src_port']}"
            self.packet_table.setItem(row, 2, QTableWidgetItem(source))
            
            # Set destination
            destination = metadata.get("dst_ip", "")
            if "dst_port" in metadata and metadata["dst_port"]:
                destination += f":{metadata['dst_port']}"
            self.packet_table.setItem(row, 3, QTableWidgetItem(destination))
            
            # Set protocol
            protocol = metadata.get("protocol", "")
            if not protocol and "layers" in metadata and metadata["layers"]:
                protocol = metadata["layers"][-1]  # Use highest layer
            self.packet_table.setItem(row, 4, QTableWidgetItem(protocol))
            
            # Set length
            length = metadata.get("size", 0)
            self.packet_table.setItem(row, 5, QTableWidgetItem(str(length)))
            
            # Set info/summary
            summary = metadata.get("summary", "")
            self.packet_table.setItem(row, 6, QTableWidgetItem(summary))
            
            # Get color for this packet
            bg_color = self.get_packet_color(metadata)
            
            # Apply color to all cells in the row
            for col in range(7):
                self.packet_table.item(row, col).setBackground(bg_color)
            
            # Auto-scroll to the new row if enabled
            if self.autoscroll_checkbox.isChecked():
                # Don't scroll for every packet - too CPU intensive with high packet rates
                # Only scroll periodically based on packet count
                if len(self.captured_packets) % 10 == 0:
                    self.packet_table.scrollToItem(self.packet_table.item(row, 0))
            
            # If this is the first packet, select it
            if row == 0:
                self.packet_table.selectRow(0)

    def update_packet_display(self):
        """Refresh the packet table after loading packets from a file."""
        self.packet_table.setRowCount(0)
        for packet in self.captured_packets:
            self.handle_packet(packet)
        # Optionally select the first packet
        if self.packet_table.rowCount() > 0:
            self.packet_table.selectRow(0)

    def on_packet_selected(self):
        """Handle packet selection in the table"""
        selected_rows = self.packet_table.selectedIndexes()
        if not selected_rows:
            return
        
        # Get the row number
        row = selected_rows[0].row()
        
        # Get the packet data
        if row < len(self.captured_packets):
            packet = self.captured_packets[row]
            self.display_packet_details(packet)
            
            # Update status bar with packet info
            protocol = packet.get("protocol", "")
            if not protocol and "layers" in packet and packet["layers"]:
                protocol = packet["layers"][-1]
            
            src = packet.get("src_ip", "")
            if "src_port" in packet and packet["src_port"]:
                src += f":{packet['src_port']}"
                
            dst = packet.get("dst_ip", "")
            if "dst_port" in packet and packet["dst_port"]:
                dst += f":{packet['dst_port']}"
                
            self.statusBar().showMessage(f"Selected: Packet #{row+1} | {protocol} | {src} → {dst} | {packet.get('size', 0)} bytes")
            
    def open_file(self) -> None:
        """Placeholder for opening saved packet files."""
        QMessageBox.information(
            self,
            "Open File",
            "Opening saved packet captures is not yet implemented in this build.",
        )

    def save_packets(self) -> None:
        """Save captured packets to a PCAP or CSV file."""
        if not self.captured_packets:
            QMessageBox.information(self, "Save Packets", "No captured packets to save.")
            return

        default_name = "pyguard_capture"
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Save Captured Packets",
            default_name,
            "PCAP Files (*.pcap);;CSV Files (*.csv)",
        )

        if not file_path:
            return

        suffix = Path(file_path).suffix.lower()
        if not suffix:
            if "pcap" in selected_filter.lower():
                suffix = ".pcap"
            else:
                suffix = ".csv"
            file_path += suffix

        try:
            if suffix == ".pcap":
                written = self._write_packets_to_pcap(self.captured_packets, file_path)
                if written == 0:
                    QMessageBox.warning(
                        self,
                        "Save Packets",
                        "No packets contained raw data suitable for PCAP export.",
                    )
                    try:
                        os.remove(file_path)
                    except OSError:
                        pass
                    return
                message = f"Saved {written} packets to {file_path}"
                QMessageBox.information(self, "Save Packets", message)
                self.statusBar().showMessage(message)
            elif suffix == ".csv":
                written = self._write_packets_to_csv(self.captured_packets, file_path)
                message = f"Saved {written} packets to {file_path}"
                QMessageBox.information(self, "Save Packets", message)
                self.statusBar().showMessage(message)
            else:
                QMessageBox.warning(
                    self,
                    "Save Packets",
                    "Unsupported file extension. Please use .pcap or .csv.",
                )
        except Exception as exc:
            logger.error("Failed to save packets: %s", exc)
            QMessageBox.critical(self, "Save Packets", f"Failed to save packets:\n{exc}")

    def clear_display(self) -> None:
        """Clear captured packet data from the UI."""
        self.captured_packets.clear()
        self.packet_table.setRowCount(0)
        self.packet_tree.clear()
        self.hex_view.clear()
        self.raw_view.clear()
        self.summary_view.clear()
        self.log_view.clear()
        self.advanced_filter_table.setRowCount(0)
        self.advanced_filter_status.setText("No packets captured yet.")
        self.statusBar().showMessage("Display cleared.")

    def set_packet_limit(self, text: str) -> None:
        """Update the in-memory packet display limit based on combo selection."""
        text = text.strip()
        if text.lower() == "unlimited":
            self.max_display_packets = float("inf")
            return

        digits = "".join(ch for ch in text if ch.isdigit())
        if digits:
            try:
                self.max_display_packets = int(digits)
            except ValueError:
                logger.warning("Invalid packet limit value: %s", text)

    def show_color_legend(self) -> None:
        """Display a comprehensive color legend dialog with detailed protocol information."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Packet Color Legend - Complete Reference")
        dialog.resize(680, 600)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        title = QLabel("Packet Color Coding System")
        title.setStyleSheet("font-weight: bold; font-size: 16pt; color: #2196F3;")
        layout.addWidget(title)

        # Build comprehensive HTML content
        html = [
            "<style>",
            "body { font-family: Arial, sans-serif; line-height: 1.6; }",
            ".sw { display:inline-block; width:32px; height:20px; border:2px solid #333; margin-right:12px; vertical-align:middle; border-radius:3px; }",
            ".row { margin-bottom:12px; padding:8px; background:#f9f9f9; border-left:3px solid #2196F3; }",
            ".protocol-name { font-weight:bold; color:#1976D2; font-size:13pt; }",
            ".protocol-desc { color:#555; margin-left:44px; }",
            ".hex-code { color:#666; font-family:monospace; font-size:10pt; }",
            "h3 { color:#1976D2; border-bottom:2px solid #E3F2FD; padding-bottom:5px; }",
            "pre { background:#f5f5f5; padding:10px; border:1px solid #ddd; border-radius:4px; font-size:10pt; }",
            ".note { background:#FFF3CD; padding:10px; border-left:4px solid #FFC107; margin:10px 0; }",
            "</style>",
            "<h3>Protocol Color Reference</h3>",
            
            "<div class='row'>",
            "<span class='sw' style='background:#FFC8C8'></span>",
            "<span class='protocol-name'>Error Packets</span>",
            "<div class='protocol-desc'>Packets with processing errors, malformed frames, or parsing failures. These may indicate network issues or corrupted data.</div>",
            "<div class='hex-code'>Color: #FFC8C8 (Light Red)</div>",
            "</div>",
            
            "<div class='row'>",
            "<span class='sw' style='background:#D2E6FF'></span>",
            "<span class='protocol-name'>HTTP Traffic (Port 80)</span>",
            "<div class='protocol-desc'>Hypertext Transfer Protocol - Unencrypted web traffic. Includes HTTP requests (GET, POST, etc.) and responses. Commonly used for web browsing.</div>",
            "<div class='hex-code'>Color: #D2E6FF (Light Blue) | Ports: 80 (source or destination)</div>",
            "</div>",
            
            "<div class='row'>",
            "<span class='sw' style='background:#B4D2FF'></span>",
            "<span class='protocol-name'>HTTPS Traffic (Port 443)</span>",
            "<div class='protocol-desc'>Hypertext Transfer Protocol Secure - Encrypted web traffic using TLS/SSL. Used for secure web browsing, API calls, and secure data transfer.</div>",
            "<div class='hex-code'>Color: #B4D2FF (Medium Blue) | Ports: 443 (source or destination)</div>",
            "</div>",
            
            "<div class='row'>",
            "<span class='sw' style='background:#FFE6C8'></span>",
            "<span class='protocol-name'>SSH Traffic (Port 22)</span>",
            "<div class='protocol-desc'>Secure Shell - Encrypted remote access protocol. Used for secure command-line access to servers and secure file transfers.</div>",
            "<div class='hex-code'>Color: #FFE6C8 (Light Orange) | Ports: 22 (source or destination)</div>",
            "</div>",
            
            "<div class='row'>",
            "<span class='sw' style='background:#FFC8E6'></span>",
            "<span class='protocol-name'>FTP Traffic (Port 21)</span>",
            "<div class='protocol-desc'>File Transfer Protocol - Used for transferring files between systems. Note: Standard FTP is unencrypted.</div>",
            "<div class='hex-code'>Color: #FFC8E6 (Light Pink) | Ports: 21 (source or destination)</div>",
            "</div>",
            
            "<div class='row'>",
            "<span class='sw' style='background:#E6D2FF'></span>",
            "<span class='protocol-name'>DNS Traffic (Port 53)</span>",
            "<div class='protocol-desc'>Domain Name System - Resolves domain names to IP addresses. Includes DNS queries and responses. Essential for internet connectivity.</div>",
            "<div class='hex-code'>Color: #E6D2FF (Light Purple) | Ports: 53 (source or destination)</div>",
            "</div>",
            
            "<div class='row'>",
            "<span class='sw' style='background:#C8FFE6'></span>",
            "<span class='protocol-name'>DHCP Traffic (Ports 67/68)</span>",
            "<div class='protocol-desc'>Dynamic Host Configuration Protocol - Automatically assigns IP addresses and network configuration to devices on a network.</div>",
            "<div class='hex-code'>Color: #C8FFE6 (Light Cyan) | Ports: 67, 68 (source or destination)</div>",
            "</div>",
            
            "<div class='row'>",
            "<span class='sw' style='background:#FFFFC8'></span>",
            "<span class='protocol-name'>ICMP Traffic</span>",
            "<div class='protocol-desc'>Internet Control Message Protocol - Network diagnostic protocol. Includes ping (echo request/reply), traceroute, and error messages.</div>",
            "<div class='hex-code'>Color: #FFFFC8 (Light Yellow) | Protocol: ICMP</div>",
            "</div>",
            
            "<div class='row'>",
            "<span class='sw' style='background:#D2FFD2'></span>",
            "<span class='protocol-name'>ARP Traffic</span>",
            "<div class='protocol-desc'>Address Resolution Protocol - Maps IP addresses to MAC addresses on local networks. Essential for local network communication.</div>",
            "<div class='hex-code'>Color: #D2FFD2 (Light Green) | Protocol: ARP</div>",
            "</div>",
            
            "<div class='row'>",
            "<span class='sw' style='background:#F0F8FF'></span>",
            "<span class='protocol-name'>TCP (Other Ports)</span>",
            "<div class='protocol-desc'>Transmission Control Protocol - Reliable, connection-oriented protocol. Includes all TCP traffic not matching specific port-based rules above.</div>",
            "<div class='hex-code'>Color: #F0F8FF (Alice Blue) | Protocol: TCP</div>",
            "</div>",
            
            "<div class='row'>",
            "<span class='sw' style='background:#F0FFF0'></span>",
            "<span class='protocol-name'>UDP (Other Ports)</span>",
            "<div class='protocol-desc'>User Datagram Protocol - Fast, connectionless protocol. Includes all UDP traffic not matching specific port-based rules above.</div>",
            "<div class='hex-code'>Color: #F0FFF0 (Honeydew) | Protocol: UDP</div>",
            "</div>",
            
            "<div class='row'>",
            "<span class='sw' style='background:#FFFFFF; border:2px solid #ccc;'></span>",
            "<span class='protocol-name'>Default / Other Protocols</span>",
            "<div class='protocol-desc'>Packets that don't match any specific coloring rule. Includes IPv6, other transport protocols, or unrecognized packet types.</div>",
            "<div class='hex-code'>Color: #FFFFFF (White) | Default background</div>",
            "</div>",
            
            "<hr style='margin:20px 0;'>",
            "<h3>Usage Tips</h3>",
            "<div class='note'>",
            "<b>Color Coding Benefits:</b><br>",
            "• Quick visual identification of protocol types at a glance<br>",
            "• Easier to spot specific traffic patterns (e.g., all HTTP in blue)<br>",
            "• Helps identify unusual protocols or unexpected traffic<br>",
            "• Colors are applied automatically based on packet analysis<br><br>",
            "<b>Note:</b> Colors are for visual reference only. You can still sort, filter, and analyze packets regardless of their color. ",
            "Click any packet row to view detailed protocol information in the packet details panel.",
            "</div>",
            
            "<h3>Quick Reference Examples</h3>",
            "<pre>",
            "🔴 Red (Error)      → Malformed or corrupted packets\n",
            "🔵 Blue (HTTP)      → Web traffic on port 80\n",
            "🔵 Dark Blue (HTTPS) → Encrypted web traffic on port 443\n",
            "🟠 Orange (SSH)     → Secure shell connections on port 22\n",
            "🟣 Purple (DNS)      → Domain name resolution on port 53\n",
            "🟡 Yellow (ICMP)     → Ping and network diagnostics\n",
            "🟢 Green (ARP)       → Local network address resolution\n",
            "⚪ White (Default)   → Other protocols or unrecognized\n",
            "</pre>",
        ]

        browser = QTextBrowser()
        browser.setHtml('\n'.join(html))
        browser.setOpenExternalLinks(True)
        browser.setReadOnly(True)
        browser.setMinimumHeight(400)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(browser)
        layout.addWidget(scroll, 1)

        # Buttons: copy legend text and close
        btn_layout = QHBoxLayout()
        copy_btn = QPushButton("📋 Copy Legend")
        copy_btn.setToolTip("Copy the complete color legend to clipboard")
        def _copy_legend():
            clipboard = QApplication.clipboard()
            clipboard.setText(browser.toPlainText())
            self.statusBar().showMessage("Color legend copied to clipboard", 3000)
        copy_btn.clicked.connect(_copy_legend)
        btn_layout.addWidget(copy_btn)
        btn_layout.addStretch(1)
        from PyQt5.QtWidgets import QDialogButtonBox
        close_buttons = QDialogButtonBox(QDialogButtonBox.Close)
        close_buttons.rejected.connect(dialog.reject)
        btn_layout.addWidget(close_buttons)
        layout.addLayout(btn_layout)

        dialog.setLayout(layout)
        dialog.exec_()

    def show_filter_help(self) -> None:
        """Show comprehensive help for capture (BPF) filters and advanced filtering."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Complete Filter Guide - BPF & Advanced Filters")
        dialog.resize(800, 700)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(15, 15, 15, 15)

        title = QLabel("Network Packet Filtering Guide")
        title.setStyleSheet("font-weight: bold; font-size: 16pt; color: #2196F3;")
        layout.addWidget(title)

        # Comprehensive HTML content
        html_parts = [
            "<style>",
            "body { font-family: Arial, sans-serif; line-height: 1.6; }",
            "h3 { color:#1976D2; border-bottom:2px solid #E3F2FD; padding-bottom:5px; margin-top:20px; }",
            "h4 { color:#424242; margin-top:15px; }",
            "pre { background:#f5f5f5; padding:12px; border:1px solid #ddd; border-radius:4px; font-size:10pt; overflow-x:auto; }",
            ".note { background:#E3F2FD; padding:10px; border-left:4px solid #2196F3; margin:10px 0; }",
            ".warning { background:#FFF3CD; padding:10px; border-left:4px solid #FFC107; margin:10px 0; }",
            ".tip { background:#E8F5E9; padding:10px; border-left:4px solid #4CAF50; margin:10px 0; }",
            "code { background:#f0f0f0; padding:2px 6px; border-radius:3px; font-family:monospace; }",
            "table { border-collapse:collapse; width:100%; margin:10px 0; }",
            "td, th { border:1px solid #ddd; padding:8px; text-align:left; }",
            "th { background:#2196F3; color:white; }",
            "</style>",
            
            "<h3>📡 BPF (Berkeley Packet Filter) - Capture-Time Filtering</h3>",
            "<div class='note'>",
            "<b>What is BPF?</b> BPF filters are applied <i>during packet capture</i> by the network interface driver. ",
            "Only packets matching the filter are captured and passed to the application. This is highly efficient ",
            "because it reduces CPU usage, memory consumption, and disk I/O at the source.",
            "</div>",
            
            "<h4>Basic BPF Syntax</h4>",
            "<table>",
            "<tr><th>Filter Expression</th><th>Description</th><th>Example</th></tr>",
            "<tr><td><code>tcp</code></td><td>Capture only TCP packets</td><td>All TCP traffic</td></tr>",
            "<tr><td><code>udp</code></td><td>Capture only UDP packets</td><td>All UDP traffic</td></tr>",
            "<tr><td><code>icmp</code></td><td>Capture ICMP packets (ping, etc.)</td><td>Network diagnostics</td></tr>",
            "<tr><td><code>arp</code></td><td>Capture ARP packets</td><td>Address resolution</td></tr>",
            "<tr><td><code>host IP</code></td><td>Packets to or from IP address</td><td><code>host 192.168.1.10</code></td></tr>",
            "<tr><td><code>src host IP</code></td><td>Packets from source IP only</td><td><code>src host 10.0.0.5</code></td></tr>",
            "<tr><td><code>dst host IP</code></td><td>Packets to destination IP only</td><td><code>dst host 10.0.0.5</code></td></tr>",
            "<tr><td><code>port N</code></td><td>Packets with source OR destination port</td><td><code>port 80</code></td></tr>",
            "<tr><td><code>src port N</code></td><td>Packets from source port only</td><td><code>src port 443</code></td></tr>",
            "<tr><td><code>dst port N</code></td><td>Packets to destination port only</td><td><code>dst port 22</code></td></tr>",
            "<tr><td><code>portrange N-M</code></td><td>Packets in port range</td><td><code>portrange 1024-2048</code></td></tr>",
            "<tr><td><code>net CIDR</code></td><td>Packets to/from network/subnet</td><td><code>net 192.168.0.0/16</code></td></tr>",
            "</table>",
            
            "<h4>Logical Operators</h4>",
            "<pre>",
            "# AND operator - both conditions must be true\n",
            "tcp and port 80                    # TCP packets on port 80\n",
            "host 192.168.1.10 and tcp          # TCP packets to/from specific host\n\n",
            "# OR operator - either condition can be true\n",
            "port 80 or port 443                # HTTP or HTTPS traffic\n",
            "tcp or udp                          # Any TCP or UDP traffic\n\n",
            "# NOT operator - exclude matching packets\n",
            "not tcp                             # All packets except TCP\n",
            "not port 22                         # All packets except SSH\n\n",
            "# Parentheses for grouping\n",
            "tcp and (port 80 or port 443)      # TCP on HTTP or HTTPS ports\n",
            "(src host 10.0.0.5) or (dst host 10.0.0.5)  # Packets involving host\n",
            "</pre>",
            
            "<h4>Advanced BPF Examples</h4>",
            "<pre>",
            "# Capture web traffic only\n",
            "tcp and (port 80 or port 443)\n\n",
            "# Capture traffic from specific subnet\n",
            "net 192.168.1.0/24\n\n",
            "# Capture DNS queries\n",
            "udp and port 53\n\n",
            "# Capture SSH connections to specific host\n",
            "tcp and dst host 192.168.1.100 and dst port 22\n\n",
            "# Capture large packets (over 1000 bytes)\n",
            "greater 1000\n\n",
            "# Capture broadcast traffic\n",
            "broadcast\n\n",
            "# Capture multicast traffic\n",
            "multicast\n",
            "</pre>",
            
            "<div class='tip'>",
            "<b>💡 Best Practice:</b> Use BPF filters to reduce the volume of captured traffic, especially on busy networks. ",
            "This improves performance and makes analysis easier.",
            "</div>",
            
            "<hr style='margin:20px 0;'>",
            
            "<h3>🔍 Advanced Filter - Post-Capture Python Expressions</h3>",
            "<div class='note'>",
            "<b>What is the Advanced Filter?</b> The Advanced Filter evaluates Python expressions against <i>already captured</i> packets. ",
            "It allows complex filtering based on packet fields, protocol layers, and packet metadata. Unlike BPF, ",
            "this filter runs after capture, so all packets must be captured first.",
            "</div>",
            
            "<h4>Available Packet Variables</h4>",
            "<table>",
            "<tr><th>Variable</th><th>Type</th><th>Description</th><th>Example Value</th></tr>",
            "<tr><td><code>src_ip</code></td><td>string</td><td>Source IP address</td><td><code>'192.168.1.10'</code></td></tr>",
            "<tr><td><code>dst_ip</code></td><td>string</td><td>Destination IP address</td><td><code>'10.0.0.5'</code></td></tr>",
            "<tr><td><code>src_port</code></td><td>int</td><td>Source port number</td><td><code>54321</code></td></tr>",
            "<tr><td><code>dst_port</code></td><td>int</td><td>Destination port number</td><td><code>80</code></td></tr>",
            "<tr><td><code>protocol</code></td><td>string</td><td>Transport protocol</td><td><code>'TCP'</code>, <code>'UDP'</code>, <code>'ICMP'</code></td></tr>",
            "<tr><td><code>size</code></td><td>int</td><td>Packet size in bytes</td><td><code>1500</code></td></tr>",
            "<tr><td><code>layers</code></td><td>string</td><td>Protocol layers (comma-separated)</td><td><code>'Ethernet,IP,TCP,HTTP'</code></td></tr>",
            "<tr><td><code>summary</code></td><td>string</td><td>Packet summary/description</td><td><code>'HTTP GET /index.html'</code></td></tr>",
            "</table>",
            
            "<h4>Basic Advanced Filter Examples</h4>",
            "<pre>",
            "# Filter HTTPS traffic (TCP port 443)\n",
            "protocol == 'TCP' and (dst_port == 443 or src_port == 443)\n\n",
            "# Filter DNS queries/responses\n",
            "'DNS' in layers\n\n",
            "# Filter packets to/from specific host\n",
            "src_ip == '192.168.1.10' or dst_ip == '192.168.1.10'\n\n",
            "# Filter large packets (possible fragmentation or data transfer)\n",
            "size >= 1500\n\n",
            "# Filter small packets (often control packets)\n",
            "size < 100\n\n",
            "# Filter HTTP requests (GET, POST, etc.)\n",
            "'HTTP' in layers and 'GET' in summary\n\n",
            "# Filter SSH connections\n",
            "protocol == 'TCP' and (dst_port == 22 or src_port == 22)\n",
            "</pre>",
            
            "<h4>Complex Advanced Filter Examples</h4>",
            "<pre>",
            "# Filter packets from specific host on specific port\n",
            "(src_ip == '10.0.0.5' or dst_ip == '10.0.0.5') and (dst_port == 22 or src_port == 22)\n\n",
            "# Filter HTTP traffic to specific destination\n",
            "'HTTP' in layers and dst_ip == '192.168.1.100' and dst_port == 80\n\n",
            "# Filter large TCP packets (possible file transfers)\n",
            "protocol == 'TCP' and size > 1000\n\n",
            "# Filter DNS queries (small DNS packets are usually queries)\n",
            "'DNS' in layers and size < 200\n\n",
            "# Filter packets with multiple protocol layers\n",
            "'HTTP' in layers and 'TCP' in layers\n\n",
            "# Filter packets NOT from local network\n",
            "not (src_ip.startswith('192.168.') or src_ip.startswith('10.') or src_ip.startswith('172.'))\n",
            "</pre>",
            
            "<h4>String Operations</h4>",
            "<pre>",
            "# Check if IP is in subnet (starts with)\n",
            "src_ip.startswith('192.168.1.')\n\n",
            "# Check if summary contains specific text\n",
            "'GET' in summary or 'POST' in summary\n\n",
            "# Check protocol layers\n",
            "'HTTP' in layers\n",
            "'TCP' in layers and 'HTTP' in layers\n",
            "</pre>",
            
            "<div class='warning'>",
            "<b>⚠️ Important Notes:</b><br>",
            "• Advanced filters run in a restricted Python environment for security<br>",
            "• Keep expressions simple and avoid complex operations<br>",
            "• All packets must be captured first (unlike BPF which filters during capture)<br>",
            "• For heavy filtering, use BPF during capture to reduce packet volume<br>",
            "• Advanced filters are case-sensitive for string comparisons",
            "</div>",
            
            "<hr style='margin:20px 0;'>",
            
            "<h3>📊 When to Use Which Filter?</h3>",
            "<table>",
            "<tr><th>Scenario</th><th>Recommended Filter</th><th>Reason</th></tr>",
            "<tr><td>High traffic network</td><td>BPF</td><td>Reduces capture load</td></tr>",
            "<tr><td>Specific protocol only</td><td>BPF</td><td>Efficient at capture time</td><td></tr>",
            "<tr><td>Complex conditions</td><td>Advanced</td><td>More flexible expressions</td></tr>",
            "<tr><td>Filter by packet content</td><td>Advanced</td><td>Can check summary/layers</td></tr>",
            "<tr><td>Filter by size</td><td>Advanced</td><td>Easy size comparisons</td></tr>",
            "<tr><td>Multiple conditions</td><td>Both</td><td>BPF for basic, Advanced for complex</td></tr>",
            "</table>",
        ]

        browser = QTextBrowser()
        browser.setHtml(''.join(html_parts))
        browser.setMinimumHeight(500)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(browser)
        layout.addWidget(scroll, 1)

        # Button row: copy examples and close
        btn_layout = QHBoxLayout()
        copy_examples = QPushButton("📋 Copy All Examples")
        copy_examples.setToolTip("Copy all filter examples to clipboard")
        def _copy_examples():
            examples_text = (
                "=== BPF Filter Examples ===\n"
                "tcp\n"
                "udp\n"
                "icmp\n"
                "host 192.168.1.10\n"
                "src host 10.0.0.5\n"
                "dst host 10.0.0.5\n"
                "port 80\n"
                "portrange 1024-2048\n"
                "net 192.168.0.0/16\n"
                "tcp and (dst port 80 or dst port 443)\n\n"
                "=== Advanced Filter Examples ===\n"
                "protocol == 'TCP' and (dst_port == 443 or src_port == 443)\n"
                "'DNS' in layers\n"
                "(src_ip == '10.0.0.5' or dst_ip == '10.0.0.5') and (dst_port == 22 or src_port == 22)\n"
                "size >= 1500\n"
                "'HTTP' in layers and 'GET' in summary\n"
            )
            QApplication.clipboard().setText(examples_text)
            self.statusBar().showMessage("All filter examples copied to clipboard", 3000)
        copy_examples.clicked.connect(_copy_examples)
        btn_layout.addWidget(copy_examples)
        btn_layout.addStretch(1)
        from PyQt5.QtWidgets import QDialogButtonBox
        close_buttons = QDialogButtonBox(QDialogButtonBox.Close)
        close_buttons.rejected.connect(dialog.reject)
        btn_layout.addWidget(close_buttons)
        layout.addLayout(btn_layout)

        dialog.setLayout(layout)
        dialog.exec_()

    def apply_advanced_filter(self) -> None:
        """Evaluate the advanced filter expression against captured packets."""
        query = self.advanced_filter_input.text().strip()

        if not query:
            self.clear_advanced_filter()
            self.update_advanced_filter_table()
            return

        if not self.captured_packets:
            self.advanced_filter_status.setText("No packets captured yet.")
            return

        self.advanced_filter_table.setRowCount(0)

        matching_packets = []
        safe_globals = {"__builtins__": {}}

        for index, packet in enumerate(self.captured_packets):
            packet_env = dict(packet)
            try:
                result = eval(query, safe_globals, packet_env)
            except Exception:
                continue
            if result:
                matching_packets.append((index, packet))

        if not matching_packets:
            self.advanced_filter_status.setText("No packets matched the query.")
            return

        self.advanced_filter_table.setRowCount(len(matching_packets))
        for row, (packet_index, packet) in enumerate(matching_packets):
            color = self.get_packet_color(packet)

            index_item = QTableWidgetItem(str(packet_index + 1))
            index_item.setData(Qt.UserRole, packet_index)
            index_item.setBackground(color)
            self.advanced_filter_table.setItem(row, 0, index_item)

            time_str = packet.get("timestamp", "")
            if isinstance(time_str, str) and len(time_str) > 19:
                time_str = time_str[:19]
            time_item = QTableWidgetItem(time_str)
            time_item.setBackground(color)
            self.advanced_filter_table.setItem(row, 1, time_item)

            src = packet.get("src_ip", "")
            if packet.get("src_port"):
                src += f":{packet['src_port']}"
            src_item = QTableWidgetItem(src)
            src_item.setBackground(color)
            self.advanced_filter_table.setItem(row, 2, src_item)

            dst = packet.get("dst_ip", "")
            if packet.get("dst_port"):
                dst += f":{packet['dst_port']}"
            dst_item = QTableWidgetItem(dst)
            dst_item.setBackground(color)
            self.advanced_filter_table.setItem(row, 3, dst_item)

            protocol = packet.get("protocol", "")
            if not protocol and packet.get("layers"):
                protocol = packet["layers"][-1]
            proto_item = QTableWidgetItem(protocol)
            proto_item.setBackground(color)
            self.advanced_filter_table.setItem(row, 4, proto_item)

            length_item = QTableWidgetItem(str(packet.get("size", 0)))
            length_item.setBackground(color)
            self.advanced_filter_table.setItem(row, 5, length_item)

            summary_item = QTableWidgetItem(packet.get("summary", ""))
            summary_item.setBackground(color)
            self.advanced_filter_table.setItem(row, 6, summary_item)

        self.advanced_filter_status.setText(f"Showing {len(matching_packets)} matching packets.")

    def show_advanced_filter_help(self) -> None:
        """Show comprehensive help dialog for the advanced filter syntax."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Advanced Filter - Complete Reference")
        dialog.resize(750, 650)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(15, 15, 15, 15)

        title = QLabel("Advanced Filter - Python Expression Guide")
        title.setStyleSheet("font-weight: bold; font-size: 16pt; color: #2196F3;")
        layout.addWidget(title)

        html_parts = [
            "<style>",
            "body { font-family: Arial, sans-serif; line-height: 1.6; }",
            "h3 { color:#1976D2; border-bottom:2px solid #E3F2FD; padding-bottom:5px; margin-top:20px; }",
            "h4 { color:#424242; margin-top:15px; }",
            "pre { background:#f5f5f5; padding:12px; border:1px solid #ddd; border-radius:4px; font-size:10pt; overflow-x:auto; }",
            ".note { background:#E3F2FD; padding:10px; border-left:4px solid #2196F3; margin:10px 0; }",
            ".warning { background:#FFF3CD; padding:10px; border-left:4px solid #FFC107; margin:10px 0; }",
            ".tip { background:#E8F5E9; padding:10px; border-left:4px solid #4CAF50; margin:10px 0; }",
            "code { background:#f0f0f0; padding:2px 6px; border-radius:3px; font-family:monospace; }",
            "table { border-collapse:collapse; width:100%; margin:10px 0; }",
            "td, th { border:1px solid #ddd; padding:8px; text-align:left; }",
            "th { background:#2196F3; color:white; }",
            "</style>",
            
            "<div class='note'>",
            "<b>What is the Advanced Filter?</b> The Advanced Filter evaluates Python expressions against each captured packet. ",
            "It runs <i>after</i> packets are captured, allowing you to filter based on packet fields, protocol layers, and metadata. ",
            "This is more flexible than BPF filters but requires all packets to be captured first.",
            "</div>",
            
            "<h3>📋 Available Packet Variables</h3>",
            "<table>",
            "<tr><th>Variable</th><th>Type</th><th>Description</th><th>Example</th></tr>",
            "<tr><td><code>src_ip</code></td><td>string</td><td>Source IP address</td><td><code>'192.168.1.10'</code></td></tr>",
            "<tr><td><code>dst_ip</code></td><td>string</td><td>Destination IP address</td><td><code>'10.0.0.5'</code></td></tr>",
            "<tr><td><code>src_port</code></td><td>int</td><td>Source port number (0 if not applicable)</td><td><code>54321</code></td></tr>",
            "<tr><td><code>dst_port</code></td><td>int</td><td>Destination port number (0 if not applicable)</td><td><code>80</code></td></tr>",
            "<tr><td><code>protocol</code></td><td>string</td><td>Transport protocol name</td><td><code>'TCP'</code>, <code>'UDP'</code>, <code>'ICMP'</code></td></tr>",
            "<tr><td><code>size</code></td><td>int</td><td>Packet size in bytes</td><td><code>1500</code></td></tr>",
            "<tr><td><code>layers</code></td><td>string</td><td>Comma-separated protocol layers</td><td><code>'Ethernet,IP,TCP,HTTP'</code></td></tr>",
            "<tr><td><code>summary</code></td><td>string</td><td>Packet summary/description</td><td><code>'HTTP GET /index.html'</code></td></tr>",
            "</table>",
            
            "<h3>🔧 Basic Filter Examples</h3>",
            "<pre>",
            "# Filter HTTPS traffic (TCP port 443)\n",
            "protocol == 'TCP' and (dst_port == 443 or src_port == 443)\n\n",
            "# Filter HTTP traffic (TCP port 80)\n",
            "protocol == 'TCP' and (dst_port == 80 or src_port == 80)\n\n",
            "# Filter DNS queries/responses\n",
            "'DNS' in layers\n\n",
            "# Filter SSH connections (port 22)\n",
            "protocol == 'TCP' and (dst_port == 22 or src_port == 22)\n\n",
            "# Filter packets to/from specific IP\n",
            "src_ip == '192.168.1.10' or dst_ip == '192.168.1.10'\n\n",
            "# Filter large packets\n",
            "size >= 1500\n\n",
            "# Filter small packets\n",
            "size < 100\n",
            "</pre>",
            
            "<h3>🎯 Complex Filter Examples</h3>",
            "<pre>",
            "# Filter HTTP requests (GET, POST, etc.)\n",
            "'HTTP' in layers and ('GET' in summary or 'POST' in summary)\n\n",
            "# Filter packets from specific host on specific port\n",
            "(src_ip == '10.0.0.5' or dst_ip == '10.0.0.5') and (dst_port == 22 or src_port == 22)\n\n",
            "# Filter HTTP traffic to specific destination\n",
            "'HTTP' in layers and dst_ip == '192.168.1.100' and dst_port == 80\n\n",
            "# Filter large TCP packets (possible file transfers)\n",
            "protocol == 'TCP' and size > 1000\n\n",
            "# Filter DNS queries (small DNS packets are usually queries)\n",
            "'DNS' in layers and size < 200\n\n",
            "# Filter packets with multiple protocol layers\n",
            "'HTTP' in layers and 'TCP' in layers\n\n",
            "# Filter packets NOT from local network\n",
            "not (src_ip.startswith('192.168.') or src_ip.startswith('10.') or src_ip.startswith('172.'))\n\n",
            "# Filter packets in specific port range\n",
            "dst_port >= 8000 and dst_port <= 9000\n",
            "</pre>",
            
            "<h3>🔤 String Operations</h3>",
            "<pre>",
            "# Check if IP is in subnet\n",
            "src_ip.startswith('192.168.1.')\n\n",
            "# Check if summary contains specific text\n",
            "'GET' in summary or 'POST' in summary\n",
            "'404' in summary  # HTTP 404 errors\n\n",
            "# Check protocol layers\n",
            "'HTTP' in layers\n",
            "'TCP' in layers and 'HTTP' in layers\n",
            "'DNS' in layers and 'UDP' in layers\n",
            "</pre>",
            
            "<h3>⚙️ Logical Operators</h3>",
            "<pre>",
            "# AND - both conditions must be true\n",
            "protocol == 'TCP' and dst_port == 443\n\n",
            "# OR - either condition can be true\n",
            "src_ip == '10.0.0.5' or dst_ip == '10.0.0.5'\n\n",
            "# NOT - exclude matching packets\n",
            "not (protocol == 'ICMP')\n",
            "not ('DNS' in layers)\n\n",
            "# Parentheses for grouping\n",
            "(src_ip == '10.0.0.5' or dst_ip == '10.0.0.5') and (dst_port == 22 or src_port == 22)\n",
            "</pre>",
            
            "<h3>📊 Comparison Operators</h3>",
            "<pre>",
            "# Equality\n",
            "protocol == 'TCP'\n",
            "dst_port == 80\n\n",
            "# Inequality\n",
            "protocol != 'UDP'\n",
            "size != 0\n\n",
            "# Greater than / Less than\n",
            "size >= 1500  # Large packets\n",
            "size < 100    # Small packets\n",
            "dst_port > 1024  # Non-privileged ports\n",
            "</pre>",
            
            "<div class='tip'>",
            "<b>💡 Tips for Effective Filtering:</b><br>",
            "• Start with simple filters and gradually add complexity<br>",
            "• Use parentheses to group conditions clearly<br>",
            "• Test filters on a small capture first<br>",
            "• Combine with BPF filters for better performance<br>",
            "• Use <code>in</code> operator for checking layers and summary text",
            "</div>",
            
            "<div class='warning'>",
            "<b>⚠️ Important Notes:</b><br>",
            "• Advanced filters run in a restricted Python environment for security<br>",
            "• Keep expressions simple - avoid complex operations<br>",
            "• All packets must be captured first (unlike BPF)<br>",
            "• For heavy filtering, use BPF during capture to reduce packet volume<br>",
            "• String comparisons are case-sensitive<br>",
            "• If no packets match, try a broader query or capture without a BPF filter first",
            "</div>",
        ]

        browser = QTextBrowser()
        browser.setHtml(''.join(html_parts))
        browser.setMinimumHeight(450)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(browser)
        layout.addWidget(scroll, 1)

        # Buttons
        btn_layout = QHBoxLayout()
        copy_btn = QPushButton("📋 Copy Examples")
        copy_btn.setToolTip("Copy filter examples to clipboard")
        def _copy_examples():
            examples_text = (
                "=== Advanced Filter Examples ===\n"
                "protocol == 'TCP' and (dst_port == 443 or src_port == 443)\n"
                "'DNS' in layers\n"
                "src_ip == '192.168.1.10' or dst_ip == '192.168.1.10'\n"
                "size >= 1500\n"
                "'HTTP' in layers and 'GET' in summary\n"
                "(src_ip == '10.0.0.5' or dst_ip == '10.0.0.5') and (dst_port == 22 or src_port == 22)\n"
                "'HTTP' in layers and dst_ip == '192.168.1.100' and dst_port == 80\n"
                "protocol == 'TCP' and size > 1000\n"
                "'DNS' in layers and size < 200\n"
            )
            QApplication.clipboard().setText(examples_text)
            self.statusBar().showMessage("Advanced filter examples copied to clipboard", 3000)
        copy_btn.clicked.connect(_copy_examples)
        btn_layout.addWidget(copy_btn)
        btn_layout.addStretch(1)
        from PyQt5.QtWidgets import QDialogButtonBox
        close_buttons = QDialogButtonBox(QDialogButtonBox.Close)
        close_buttons.rejected.connect(dialog.reject)
        btn_layout.addWidget(close_buttons)
        layout.addLayout(btn_layout)

        dialog.setLayout(layout)
        dialog.exec_()

    def clear_advanced_filter(self) -> None:
        """Reset the advanced filter UI components."""
        self.advanced_filter_input.clear()
        self.advanced_filter_table.setRowCount(0)
        self.advanced_filter_status.setText("Advanced filter cleared.")

    def on_advanced_filter_selection(self) -> None:
        """Sync the main packet view when an advanced filter row is selected."""
        selected = self.advanced_filter_table.selectedIndexes()
        if not selected:
            return

        row = selected[0].row()
        index_item = self.advanced_filter_table.item(row, 0)
        if not index_item:
            return

        packet_index = index_item.data(Qt.UserRole)
        if packet_index is None:
            try:
                packet_index = int(index_item.text()) - 1
            except (ValueError, TypeError):
                return

        if 0 <= packet_index < len(self.captured_packets):
            self.packet_table.selectRow(packet_index)
            self.display_packet_details(self.captured_packets[packet_index])

    def load_ui_state(self) -> None:
        """Placeholder for restoring persisted UI state."""
        # Original implementation relied on QSettings; omitted in this build.
        pass
    def on_tab_changed(self, index):
        """Handle tab change in the secondary tabs"""
        # If the Database Status tab is selected, update the status
        if self.secondary_tabs.widget(index) == self.db_status_view:
            self.update_db_status()
            
    def on_details_tab_changed(self, index):
        """Handle tab change in the details tabs"""
        # If the Advanced Filter tab is selected, update it
        if self.details_tabs.widget(index) == self.advanced_filter_widget:
            # Only update if no filter is applied
            if not self.advanced_filter_input.text().strip():
                self.update_advanced_filter_table()
    
    def show_packet_context_menu(self, position):
        """Show context menu for packet list"""
        # Get selected row
        selected_rows = self.packet_table.selectedIndexes()
        if not selected_rows:
            return
            
        row = selected_rows[0].row()
        
        # Create context menu
        context_menu = QMenu(self)
        
        # Add actions
        copy_action = QAction("Copy Selected Packet", self)
        copy_action.triggered.connect(lambda: self.copy_packet_to_clipboard(row))
        context_menu.addAction(copy_action)
        
        follow_stream_action = QAction("Follow TCP/UDP Stream", self)
        follow_stream_action.triggered.connect(lambda: self.follow_stream(row))
        context_menu.addAction(follow_stream_action)
        
        filter_by_ip_action = QAction("Filter by IP", self)
        filter_by_ip_action.triggered.connect(lambda: self.filter_by_ip(row))
        context_menu.addAction(filter_by_ip_action)
        
        filter_by_port_action = QAction("Filter by Port", self)
        filter_by_port_action.triggered.connect(lambda: self.filter_by_port(row))
        context_menu.addAction(filter_by_port_action)
        
        filter_by_protocol_action = QAction("Filter by Protocol", self)
        filter_by_protocol_action.triggered.connect(lambda: self.filter_by_protocol(row))
        context_menu.addAction(filter_by_protocol_action)
        
        # Show context menu
        context_menu.exec_(self.packet_table.mapToGlobal(position))
    
    def copy_packet_to_clipboard(self, row):
        """Copy packet details to clipboard"""
        if row < len(self.captured_packets):
            packet = self.captured_packets[row]
            
            # Format packet summary
            summary = f"Packet #{row+1}\n"
            summary += f"Time: {packet.get('timestamp', '')}\n"
            summary += f"Protocol: {packet.get('protocol', '')}\n"
            summary += f"Source: {packet.get('src_ip', '')}"
            if "src_port" in packet and packet["src_port"]:
                summary += f":{packet['src_port']}"
            summary += f"\nDestination: {packet.get('dst_ip', '')}"
            if "dst_port" in packet and packet["dst_port"]:
                summary += f":{packet['dst_port']}"
            summary += f"\nLength: {packet.get('size', 0)} bytes\n"
            summary += f"Summary: {packet.get('summary', '')}\n"
            
            # Copy to clipboard
            clipboard = QApplication.clipboard()
            clipboard.setText(summary)
            
            self.statusBar().showMessage("Packet details copied to clipboard")
    
    def follow_stream(self, row):
        """Follow TCP/UDP stream"""
        if row < len(self.captured_packets):
            packet = self.captured_packets[row]
            
            # Check if TCP or UDP
            if packet.get("protocol") not in ["TCP", "UDP"]:
                QMessageBox.information(self, "Follow Stream", "Only TCP and UDP streams can be followed.")
                return
            
            # Get IP and port information
            src_ip = packet.get("src_ip", "")
            src_port = packet.get("src_port", "")
            dst_ip = packet.get("dst_ip", "")
            dst_port = packet.get("dst_port", "")
            
            if not (src_ip and src_port and dst_ip and dst_port):
                QMessageBox.information(self, "Follow Stream", "Missing IP or port information.")
                return
            
            # Create filter for this stream
            stream_filter = f"({src_ip}:{src_port} <-> {dst_ip}:{dst_port})"
            
            # Apply filter
            self.filter_text.setText(stream_filter)
            self.apply_filter()
    
    def filter_by_ip(self, row):
        """Filter by IP address"""
        if row < len(self.captured_packets):
            packet = self.captured_packets[row]
            
            # Create menu to select which IP to filter by
            ip_menu = QMenu(self)
            
            src_ip = packet.get("src_ip", "")
            if src_ip:
                src_action = QAction(f"Source: {src_ip}", self)
                src_action.triggered.connect(lambda: self.set_filter(src_ip))
                ip_menu.addAction(src_action)
            
            dst_ip = packet.get("dst_ip", "")
            if dst_ip:
                dst_action = QAction(f"Destination: {dst_ip}", self)
                dst_action.triggered.connect(lambda: self.set_filter(dst_ip))
                ip_menu.addAction(dst_action)
            
            if src_ip and dst_ip:
                both_action = QAction(f"Both: {src_ip} or {dst_ip}", self)
                both_action.triggered.connect(lambda: self.set_filter(f"{src_ip} {dst_ip}"))
                ip_menu.addAction(both_action)
            
            # Show menu
            cursor_pos = QCursor.pos()
            ip_menu.exec_(cursor_pos)
    
    def filter_by_port(self, row):
        """Filter by port"""
        if row < len(self.captured_packets):
            packet = self.captured_packets[row]
            
            # Create menu to select which port to filter by
            port_menu = QMenu(self)
            
            src_port = packet.get("src_port", "")
            if src_port:
                src_action = QAction(f"Source Port: {src_port}", self)
                src_action.triggered.connect(lambda: self.set_filter(f"port {src_port}"))
                port_menu.addAction(src_action)
            
            dst_port = packet.get("dst_port", "")
            if dst_port:
                dst_action = QAction(f"Destination Port: {dst_port}", self)
                dst_action.triggered.connect(lambda: self.set_filter(f"port {dst_port}"))
                port_menu.addAction(dst_action)
            
            if src_port and dst_port:
                both_action = QAction(f"Both Ports: {src_port} or {dst_port}", self)
                both_action.triggered.connect(lambda: self.set_filter(f"port {src_port} port {dst_port}"))
                port_menu.addAction(both_action)
            
            # Show menu
            cursor_pos = QCursor.pos()
            port_menu.exec_(cursor_pos)

    def filter_by_protocol(self, row):
        """Filter by protocol"""
        if row < len(self.captured_packets):
            packet = self.captured_packets[row]
            
            protocol = packet.get("protocol", "")
            if not protocol and "layers" in packet and packet["layers"]:
                protocol = packet["layers"][-1]
            
            if protocol:
                self.set_filter(protocol.lower())
    
    def set_filter(self, filter_text):
        """Set filter text and apply"""
        self.filter_text.setText(filter_text)
        self.apply_filter()

    def apply_filter(self):
        """Apply the current filter to the displayed packets"""
        filter_text = self.filter_text.text().strip().lower()
        if not filter_text:
            # No filter - show all packets
            for row in range(self.packet_table.rowCount()):
                self.packet_table.setRowHidden(row, False)
            return

        # Apply filter - hide packets that don't match
        for row in range(self.packet_table.rowCount()):
            if row < len(self.captured_packets):
                packet = self.captured_packets[row]
                # Simple text-based filtering
                packet_text = " ".join([
                    str(packet.get("protocol", "")),
                    str(packet.get("src_ip", "")),
                    str(packet.get("dst_ip", "")),
                    str(packet.get("src_port", "")),
                    str(packet.get("dst_port", "")),
                    str(packet.get("summary", ""))
                ]).lower()

                # Show row if filter text is found in packet text
                show = filter_text in packet_text
                self.packet_table.setRowHidden(row, not show)
            else:
                # Hide row if no corresponding packet
                self.packet_table.setRowHidden(row, True)

    def clear_filter(self):
        """Clear the active filter and show every packet again."""
        self.filter_text.clear()
        for row in range(self.packet_table.rowCount()):
            self.packet_table.setRowHidden(row, False)
        self.statusBar().showMessage(f"Filter cleared. Showing all {self.packet_table.rowCount()} packets.")

    def display_packet_details(self, packet):
        """Display detailed information about the selected packet"""
        # Clear previous details
        self.packet_tree.clear()
        self.hex_view.clear()
        self.raw_view.clear()
        self.summary_view.clear()

        # Display protocol tree
        self.populate_protocol_tree(packet)

        # Display hex dump
        if "hex_dump" in packet:
            self.hex_view.setText(packet["hex_dump"])

        # Display raw data
        if "http_data" in packet:
            self.raw_view.setText(packet["http_data"])
        elif "payload" in packet:
            self.raw_view.setText(packet["payload"])

        # Display summary information
        self.populate_summary_view(packet)

    def populate_summary_view(self, packet):
        """Populate the summary view with packet details"""
        summary_text = f"""Packet Summary:
Frame Number: {packet.get('frame_number', 'N/A')}
Timestamp: {packet.get('timestamp', 'N/A')}
Size: {packet.get('size', 0)} bytes

Ethernet:
  Source MAC: {packet.get('mac_src', 'N/A')}
  Destination MAC: {packet.get('mac_dst', 'N/A')}
  EtherType: {packet.get('eth_type', 'N/A')}

Network:
  Source IP: {packet.get('src_ip', 'N/A')}
  Destination IP: {packet.get('dst_ip', 'N/A')}
  Protocol: {packet.get('protocol', 'N/A')}

Transport:
  Source Port: {packet.get('src_port', 'N/A')}
  Destination Port: {packet.get('dst_port', 'N/A')}

Layers: {', '.join(packet.get('layers', []))}
"""
        self.summary_view.setText(summary_text)

    def populate_protocol_tree(self, packet):
        """Populate the protocol tree with packet details"""
        # Add frame item (top level)
        frame_item = QTreeWidgetItem(self.packet_tree)
        frame_item.setText(0, f"Frame {packet.get('frame_number', 1)}")
        frame_item.setText(1, f"{packet.get('size', 0)} bytes captured")
        frame_item.setExpanded(True)
        frame_item.setBackground(0, QColor("#e6f2ff"))  # Light blue background
        frame_item.setBackground(1, QColor("#e6f2ff"))

        # Add timestamp
        timestamp_item = QTreeWidgetItem(frame_item)
        timestamp_item.setText(0, "Timestamp")
        timestamp_item.setText(1, packet.get("timestamp", ""))

        # Add protocol layers with color coding
        if "protocol_tree" in packet:
            for layer in packet["protocol_tree"]:
                layer_name = layer.get("layer", "Unknown")
                layer_item = QTreeWidgetItem(self.packet_tree)
                layer_item.setText(0, layer_name)
                layer_item.setText(1, "")
                layer_item.setExpanded(True)

                # Color code by layer type
                if layer_name == "Ethernet":
                    layer_item.setBackground(0, QColor("#f0f0ff"))  # Very light blue
                    layer_item.setBackground(1, QColor("#f0f0ff"))
                elif layer_name in ["IP", "IPv4", "IPv6"]:
                    layer_item.setBackground(0, QColor("#f0fff0"))  # Very light green
                    layer_item.setBackground(1, QColor("#f0fff0"))
                elif layer_name in ["TCP", "UDP"]:
                    layer_item.setBackground(0, QColor("#fff0f0"))  # Very light red
                    layer_item.setBackground(1, QColor("#fff0f0"))
                elif layer_name in ["HTTP", "DNS", "TLS"]:
                    layer_item.setBackground(0, QColor("#fffff0"))  # Very light yellow
                    layer_item.setBackground(1, QColor("#fffff0"))

                # Add fields for this layer
                for field_name, field_value in layer.get("fields", {}).items():
                    field_item = QTreeWidgetItem(layer_item)
                    field_item.setText(0, field_name)
                    field_item.setText(1, str(field_value))

    def update_ui(self):
        """Periodic UI refresh for titles, tabs, and resource info."""
        packet_count = len(self.captured_packets)
        queue_size = self.packet_queue.qsize()

        if queue_size > 0:
            self.setWindowTitle(f"PyGuard Desktop - {packet_count} packets captured ({queue_size} in queue)")
        else:
            self.setWindowTitle(f"PyGuard Desktop - {packet_count} packets captured")

        if (
            hasattr(self, "secondary_tabs")
            and self.secondary_tabs.currentWidget() == self.db_status_view
        ):
            self.update_db_status()

        try:
            import psutil

            process = psutil.Process()
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / (1024 * 1024)

            current_msg = self.statusBar().currentMessage()
            if current_msg:
                self.statusBar().showMessage(f"{current_msg} | Memory: {memory_mb:.1f} MB")
            else:
                self.statusBar().showMessage(f"Memory: {memory_mb:.1f} MB")
        except Exception:
            pass


def main():
    """Main entry point for the PyGuard Desktop Application"""
    import sys

    app = QApplication(sys.argv)
    window = DesktopApp()
    window.show()
    return app.exec_()