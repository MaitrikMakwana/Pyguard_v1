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

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QComboBox, QTextEdit, QTabWidget, QSplitter,
    QGroupBox, QFormLayout, QCheckBox, QMessageBox, QInputDialog,
    QTableWidget, QTableWidgetItem, QHeaderView, QMenu, QAction,
    QFileDialog, QDialog, QRadioButton, QSpinBox, QTreeWidget, 
    QTreeWidgetItem, QProgressBar, QStatusBar, QLineEdit, QToolBar,
    QToolButton, QSizePolicy, QFrame, QTextBrowser, QProgressDialog
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
                
                # Start sniffing packets
                sniff(
                    iface=self.interface,
                    filter=self.filter_expression if self.filter_expression else None,
                    prn=self._packet_callback,
                    store=0,  # Don't store packets in memory
                    stop_filter=lambda x: not self.running  # Stop when self.running is False
                )
                
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
        self.running = False
    
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
        self.max_display_packets = 100000  # Maximum number of packets to display
        self.packet_buffer_size = 1000  # Process packets in batches
        self.display_update_interval = 100  # ms
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
        
        # Initialize UI
        self.init_ui()
        
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
        
        save_action = QAction("💾 Save", self)
        save_action.setToolTip("Save captured packets")
        save_action.triggered.connect(self.save_packets)
        self.toolbar.addAction(save_action)
        
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
        self.packet_limit_combo.setCurrentIndex(2)  # Default to 100,000
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
    
    def populate_interfaces(self):
        """Populate the interface combo box with network interfaces"""
        self.interface_combo.clear()
        
        try:
            # Use scapy to get actual network interfaces
            from scapy.all import get_if_list, get_if_addr, conf
            
            # Get list of interfaces
            interfaces = []
            
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
                            interfaces.append(f"{iface} ({ip})")
                        else:
                            # Add interface without IP
                            interfaces.append(iface)
                    except:
                        # If we can't get IP, just add the interface name
                        interfaces.append(iface)
                
            except Exception as e:
                logger.warning(f"Could not get interfaces from scapy: {e}")
                
                # Fall back to common interface names
                if sys.platform == 'win32':
                    # Common Windows interface names
                    interfaces = [
                        "Ethernet", "Wi-Fi", "Local Area Connection", 
                        "Wireless Network Connection", "eth0", "wlan0"
                    ]
                    
                    # Add some numbered interfaces that might exist
                    for i in range(5):
                        interfaces.append(f"Ethernet {i}")
                        interfaces.append(f"Wi-Fi {i}")
                else:
                    # Common Linux/macOS interface names
                    interfaces = ["eth0", "eth1", "wlan0", "wlan1", "en0", "en1", "lo"]
            
            # Add interfaces to combo box
            for interface in interfaces:
                self.interface_combo.addItem(interface)
            
            # Add option to manually enter interface name
            self.interface_combo.addItem("-- Enter manually --")
            
            # Connect to the combo box change event
            self.interface_combo.currentTextChanged.connect(self.on_interface_changed)
            
            logger.info(f"Added {len(interfaces)} interface options")
        
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
                self.capture_thread.stop()
                
                # Update UI
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
                
                logger.info("Capture stopped")
        
        except Exception as e:
            logger.error(f"Error stopping capture: {e}")
            self.statusBar().showMessage(f"Error: {e}")
    
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
                    
                    # Highlight important fields
                    if field_name in ["src", "dst", "sport", "dport", "flags", "type", "code"]:
                        font = field_item.font(0)
                        font.setBold(True)
                        field_item.setFont(0, font)
        else:
            # Fallback if protocol_tree is not available
            for key, value in packet.items():
                if key not in ["hex_dump", "protocol_tree", "summary", "layers", "packet_data"] and not isinstance(value, (dict, list)):
                    item = QTreeWidgetItem(self.packet_tree)
                    item.setText(0, key)
                    item.setText(1, str(value))
    
    def populate_summary_view(self, packet):
        """Populate the summary view with packet details"""
        # Create HTML summary
        html = "<html><body style='font-family: Arial, sans-serif;'>"
        
        # Add packet header
        html += f"<h2 style='color: #0078d7;'>Packet #{packet.get('frame_number', 1)}</h2>"
        
        # Add packet summary
        html += f"<p style='font-size: 14px;'><b>Summary:</b> {packet.get('summary', 'N/A')}</p>"
        
        # Add timestamp
        html += f"<p><b>Time:</b> {packet.get('timestamp', 'N/A')}</p>"
        
        # Add size
        html += f"<p><b>Size:</b> {packet.get('size', 0)} bytes</p>"
        
        # Add protocol stack
        if "layers" in packet:
            html += "<p><b>Protocol Stack:</b> "
            html += " &rarr; ".join(packet["layers"])
            html += "</p>"
        
        # Add source and destination
        html += "<h3 style='color: #0078d7; margin-top: 20px;'>Addressing</h3>"
        
        if "mac_src" in packet and "mac_dst" in packet:
            html += f"<p><b>MAC Source:</b> {packet.get('mac_src', 'N/A')}</p>"
            html += f"<p><b>MAC Destination:</b> {packet.get('mac_dst', 'N/A')}</p>"
        
        if "src_ip" in packet and "dst_ip" in packet:
            html += f"<p><b>IP Source:</b> {packet.get('src_ip', 'N/A')}"
            if "src_port" in packet and packet["src_port"]:
                html += f":{packet['src_port']}"
            html += "</p>"
            
            html += f"<p><b>IP Destination:</b> {packet.get('dst_ip', 'N/A')}"
            if "dst_port" in packet and packet["dst_port"]:
                html += f":{packet['dst_port']}"
            html += "</p>"
        
        # Add protocol-specific details
        protocol = packet.get("protocol", "")
        if protocol:
            html += f"<h3 style='color: #0078d7; margin-top: 20px;'>{protocol} Details</h3>"
            
            if protocol == "TCP":
                html += "<table border='0' cellpadding='3' style='border-collapse: collapse; width: 100%;'>"
                html += "<tr style='background-color: #f0f0f0;'><th style='text-align: left;'>Field</th><th style='text-align: left;'>Value</th></tr>"
                
                if "seq" in packet:
                    html += f"<tr><td><b>Sequence Number:</b></td><td>{packet.get('seq', 'N/A')}</td></tr>"
                if "ack" in packet:
                    html += f"<tr><td><b>Acknowledgment Number:</b></td><td>{packet.get('ack', 'N/A')}</td></tr>"
                if "window" in packet:
                    html += f"<tr><td><b>Window Size:</b></td><td>{packet.get('window', 'N/A')}</td></tr>"
                if "tcp_flags" in packet:
                    html += f"<tr><td><b>Flags:</b></td><td>{' '.join(packet.get('tcp_flags', []))}</td></tr>"
                
                html += "</table>"
            
            elif protocol == "UDP":
                html += "<table border='0' cellpadding='3' style='border-collapse: collapse; width: 100%;'>"
                html += "<tr style='background-color: #f0f0f0;'><th style='text-align: left;'>Field</th><th style='text-align: left;'>Value</th></tr>"
                
                if "length" in packet:
                    html += f"<tr><td><b>Length:</b></td><td>{packet.get('length', 'N/A')}</td></tr>"
                
                html += "</table>"
            
            elif protocol == "ICMP":
                html += "<table border='0' cellpadding='3' style='border-collapse: collapse; width: 100%;'>"
                html += "<tr style='background-color: #f0f0f0;'><th style='text-align: left;'>Field</th><th style='text-align: left;'>Value</th></tr>"
                
                if "icmp_type" in packet:
                    icmp_type = packet.get('icmp_type', 'N/A')
                    icmp_type_name = {
                        0: "Echo Reply",
                        3: "Destination Unreachable",
                        5: "Redirect",
                        8: "Echo Request",
                        11: "Time Exceeded"
                    }.get(icmp_type, f"Type {icmp_type}")
                    
                    html += f"<tr><td><b>Type:</b></td><td>{icmp_type} ({icmp_type_name})</td></tr>"
                
                if "icmp_code" in packet:
                    html += f"<tr><td><b>Code:</b></td><td>{packet.get('icmp_code', 'N/A')}</td></tr>"
                
                html += "</table>"
            
            elif protocol == "ARP":
                html += "<table border='0' cellpadding='3' style='border-collapse: collapse; width: 100%;'>"
                html += "<tr style='background-color: #f0f0f0;'><th style='text-align: left;'>Field</th><th style='text-align: left;'>Value</th></tr>"
                
                if "arp_op" in packet:
                    arp_op = packet.get('arp_op', 'N/A')
                    arp_op_name = "Request" if arp_op == 1 else "Reply" if arp_op == 2 else f"Operation {arp_op}"
                    html += f"<tr><td><b>Operation:</b></td><td>{arp_op} ({arp_op_name})</td></tr>"
                
                if "arp_hwsrc" in packet:
                    html += f"<tr><td><b>Hardware Source:</b></td><td>{packet.get('arp_hwsrc', 'N/A')}</td></tr>"
                if "arp_hwdst" in packet:
                    html += f"<tr><td><b>Hardware Destination:</b></td><td>{packet.get('arp_hwdst', 'N/A')}</td></tr>"
                if "arp_psrc" in packet:
                    html += f"<tr><td><b>Protocol Source:</b></td><td>{packet.get('arp_psrc', 'N/A')}</td></tr>"
                if "arp_pdst" in packet:
                    html += f"<tr><td><b>Protocol Destination:</b></td><td>{packet.get('arp_pdst', 'N/A')}</td></tr>"
                
                html += "</table>"
        
        # Add application layer details
        if "HTTP" in packet.get("layers", []) and "http_data" in packet:
            html += "<h3 style='color: #0078d7; margin-top: 20px;'>HTTP Details</h3>"
            html += f"<pre style='background-color: #f8f8f8; padding: 10px; border: 1px solid #ddd; overflow: auto;'>{packet['http_data']}</pre>"
        
        if "DNS" in packet.get("layers", []) and "dns" in packet:
            html += "<h3 style='color: #0078d7; margin-top: 20px;'>DNS Details</h3>"
            dns = packet["dns"]
            
            html += "<table border='0' cellpadding='3' style='border-collapse: collapse; width: 100%;'>"
            html += "<tr style='background-color: #f0f0f0;'><th style='text-align: left;'>Field</th><th style='text-align: left;'>Value</th></tr>"
            
            html += f"<tr><td><b>Transaction ID:</b></td><td>{dns.get('id', 'N/A')}</td></tr>"
            html += f"<tr><td><b>Type:</b></td><td>{dns.get('query_type', 'N/A')}</td></tr>"
            
            if "query_name" in dns:
                html += f"<tr><td><b>Query Name:</b></td><td>{dns.get('query_name', 'N/A')}</td></tr>"
            
            html += "</table>"
        
        html += "</body></html>"
        
        # Set HTML content
        self.summary_view.setHtml(html)
    
    def update_status(self, stats):
        """Update status display with capture statistics"""
        try:
            # Update status label with color coding
            if self.capture_thread and self.capture_thread.isRunning():
                self.status_label.setText("Running")
                self.status_label.setStyleSheet("color: #388e3c; font-weight: bold;")  # Green for running
            else:
                self.status_label.setText("Stopped")
                self.status_label.setStyleSheet("color: #d32f2f; font-weight: bold;")  # Red for stopped
            
            # Update packet statistics
            packets_captured = stats.get("packets_captured", 0)
            self.packets_label.setText(f"Packets: {packets_captured:,}")
            
            # Update bytes captured
            bytes_captured = stats.get("bytes_captured", 0)
            if bytes_captured < 1024:
                self.bytes_label.setText(f"Bytes: {bytes_captured:,} B")
            elif bytes_captured < 1024 * 1024:
                self.bytes_label.setText(f"Bytes: {bytes_captured / 1024:.1f} KB")
            else:
                self.bytes_label.setText(f"Bytes: {bytes_captured / (1024 * 1024):.1f} MB")
            
            # Update rate
            if stats.get("start_time"):
                elapsed = time.time() - stats["start_time"]
                if elapsed > 0:
                    rate = stats.get("packets_captured", 0) / elapsed
                    self.rate_label.setText(f"Rate: {rate:.1f}/s")
            
            # Update protocol counters from our internal stats
            # (We maintain these ourselves in update_protocol_stats)
            self.tcp_label.setText(f"TCP: {self.protocol_stats['tcp_packets']:,}")
            self.udp_label.setText(f"UDP: {self.protocol_stats['udp_packets']:,}")
            self.icmp_label.setText(f"ICMP: {self.protocol_stats['icmp_packets']:,}")
            other_count = self.protocol_stats['other_packets']
            self.other_label.setText(f"Other: {other_count:,}")
            
            # Update status bar
            if stats.get("start_time"):
                elapsed = time.time() - stats["start_time"]
                elapsed_str = time.strftime("%H:%M:%S", time.gmtime(elapsed))
                
                # Calculate packet rate for last second
                try:
                    if hasattr(self, 'last_packet_count') and hasattr(self, 'last_update_time'):
                        time_diff = time.time() - self.last_update_time
                        if time_diff > 0:
                            recent_rate = (packets_captured - self.last_packet_count) / time_diff
                            status_msg = f"Running for {elapsed_str} | Current rate: {recent_rate:.1f} packets/sec"
                        else:
                            status_msg = f"Running for {elapsed_str}"
                    else:
                        status_msg = f"Running for {elapsed_str}"
                except Exception as e:
                    # Fallback if there's any error in formatting
                    status_msg = f"Running for {elapsed_str}"
                    logger.error(f"Error formatting status message: {e}")
                
                self.statusBar().showMessage(status_msg)
                
                # Store current values for next update
                self.last_packet_count = packets_captured
                self.last_update_time = time.time()
        
        except Exception as e:
            logger.error(f"Error updating status: {e}")
    
    def update_ui(self):
        """Update UI elements periodically"""
        # Update packet count in title bar
        packet_count = len(self.captured_packets)
        queue_size = self.packet_queue.qsize()
        
        if queue_size > 0:
            self.setWindowTitle(f"PyGuard Desktop - {packet_count} packets captured ({queue_size} in queue)")
        else:
            self.setWindowTitle(f"PyGuard Desktop - {packet_count} packets captured")
        
        # Update database status if the tab is visible
        if self.secondary_tabs.currentWidget() == self.db_status_view:
            self.update_db_status()
        
        # Update status bar with memory usage
        try:
            import psutil
            process = psutil.Process()
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / (1024 * 1024)
            
            # Update status message with memory usage
            current_msg = self.statusBar().currentMessage()
            if current_msg:
                self.statusBar().showMessage(f"{current_msg} | Memory: {memory_mb:.1f} MB")
            else:
                self.statusBar().showMessage(f"Memory: {memory_mb:.1f} MB")
        except:
            pass
            
    def update_db_status(self):
        """Update database status information"""
        try:
            import yaml
            import psycopg2
            
            # Load configuration
            config_path = "config.yaml"
            try:
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)
            except Exception as e:
                self.db_status_view.setHtml(f"""
                <h2>Database Status</h2>
                <p style="color: red;">Error loading configuration: {e}</p>
                <p>Could not load configuration from {config_path}</p>
                <p>The desktop application does not directly store data in the database.</p>
                <p>To store captured data in PostgreSQL, use the main PyGuard application:</p>
                <pre>python -m pyguard.main</pre>
                """)
                return
                
            # Get database configuration
            db_config = config.get('database', {})
            if not db_config or not db_config.get('enabled', False):
                self.db_status_view.setHtml(f"""
                <h2>Database Status</h2>
                <p style="color: orange;">Database storage is disabled in configuration.</p>
                <p>The desktop application does not directly store data in the database.</p>
                <p>To enable database storage:</p>
                <ol>
                    <li>Edit config.yaml</li>
                    <li>Set database.enabled to true</li>
                    <li>Configure database connection parameters</li>
                    <li>Run the main PyGuard application: <pre>python -m pyguard.main</pre></li>
                </ol>
                """)
                return
                
            # Try to connect to the database
            try:
                conn = psycopg2.connect(
                    host=db_config['host'],
                    port=db_config['port'],
                    dbname=db_config['name'],
                    user=db_config['user'],
                    password=db_config['password'],
                    connect_timeout=3  # Short timeout to avoid UI freezing
                )
                
                # Create a cursor
                cursor = conn.cursor()
                
                # Check database connection
                cursor.execute("SELECT version();")
                version = cursor.fetchone()[0]
                
                # Get table information
                cursor.execute("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_schema = 'public'
                """)
                tables = cursor.fetchall()
                
                # Get packet count
                packet_count = 0
                flow_count = 0
                
                for table in tables:
                    table_name = table[0]
                    if table_name == 'packets':
                        cursor.execute("SELECT COUNT(*) FROM packets")
                        packet_count = cursor.fetchone()[0]
                    elif table_name == 'flows':
                        cursor.execute("SELECT COUNT(*) FROM flows")
                        flow_count = cursor.fetchone()[0]
                
                # Get the most recent packets
                recent_packets = []
                if 'packets' in [t[0] for t in tables]:
                    cursor.execute("""
                        SELECT timestamp, src_ip, dst_ip, protocol_name, src_port, dst_port
                        FROM packets
                        ORDER BY timestamp DESC
                        LIMIT 10
                    """)
                    recent_packets = cursor.fetchall()
                
                # Close cursor and connection
                cursor.close()
                conn.close()
                
                # Build HTML status
                html = f"""
                <h2>Database Status</h2>
                <p style="color: green;">✓ Connected to PostgreSQL</p>
                <p><b>Version:</b> {version}</p>
                <p><b>Connection:</b> {db_config['host']}:{db_config['port']}/{db_config['name']}</p>
                <p><b>Tables:</b> {', '.join([t[0] for t in tables])}</p>
                <p><b>Packet Count:</b> {packet_count:,}</p>
                <p><b>Flow Count:</b> {flow_count:,}</p>
                
                <h3>Note</h3>
                <p>The desktop application does not directly store data in the database.</p>
                <p>To store captured data in PostgreSQL, use the main PyGuard application:</p>
                <pre>python -m pyguard.main</pre>
                """
                
                if recent_packets:
                    html += """
                    <h3>Recent Packets in Database</h3>
                    <table border="1" cellpadding="5" style="border-collapse: collapse; width: 100%;">
                        <tr style="background-color: #f0f0f0;">
                            <th>Timestamp</th>
                            <th>Source</th>
                            <th>Destination</th>
                            <th>Protocol</th>
                        </tr>
                    """
                    
                    for packet in recent_packets:
                        timestamp, src_ip, dst_ip, protocol, src_port, dst_port = packet
                        source = f"{src_ip}:{src_port}" if src_port else src_ip
                        destination = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
                        html += f"""
                        <tr>
                            <td>{timestamp}</td>
                            <td>{source}</td>
                            <td>{destination}</td>
                            <td>{protocol}</td>
                        </tr>
                        """
                    
                    html += "</table>"
                
                self.db_status_view.setHtml(html)
                
            except Exception as e:
                self.db_status_view.setHtml(f"""
                <h2>Database Status</h2>
                <p style="color: red;">✗ Database Connection Error</p>
                <p><b>Error:</b> {e}</p>
                <p><b>Connection:</b> {db_config.get('host', 'N/A')}:{db_config.get('port', 'N/A')}/{db_config.get('name', 'N/A')}</p>
                
                <h3>Troubleshooting</h3>
                <ol>
                    <li>Verify PostgreSQL is running</li>
                    <li>Check connection parameters in config.yaml</li>
                    <li>Ensure the database exists</li>
                    <li>Run the database setup script:
                        <pre>python scripts/setup_database.py</pre>
                    </li>
                    <li>Check database status:
                        <pre>python check_database.py</pre>
                    </li>
                </ol>
                
                <h3>Note</h3>
                <p>The desktop application does not directly store data in the database.</p>
                <p>To store captured data in PostgreSQL, use the main PyGuard application:</p>
                <pre>python -m pyguard.main</pre>
                """)
                
        except Exception as e:
            self.db_status_view.setHtml(f"""
            <h2>Database Status</h2>
            <p style="color: red;">Error checking database status: {e}</p>
            
            <h3>Note</h3>
            <p>The desktop application does not directly store data in the database.</p>
            <p>To store captured data in PostgreSQL, use the main PyGuard application:</p>
            <pre>python -m pyguard.main</pre>
            """)
    
    def apply_filter(self):
        """Apply filter to the packet list"""
        filter_text = self.filter_text.text().strip().lower()
        if not filter_text:
            # If filter is empty, show all packets
            for row in range(self.packet_table.rowCount()):
                self.packet_table.setRowHidden(row, False)
            return
        
        # Hide rows that don't match the filter
        for row in range(self.packet_table.rowCount()):
            match = False
            
            # Check each column for a match
            for col in range(1, 7):  # Skip the packet number column
                cell_text = self.packet_table.item(row, col).text().lower()
                if filter_text in cell_text:
                    match = True
                    break
            
            # Hide or show the row based on the match
            self.packet_table.setRowHidden(row, not match)
    
    def clear_filter(self):
        """Clear the filter and show all packets"""
        self.filter_text.clear()
        for row in range(self.packet_table.rowCount()):
            self.packet_table.setRowHidden(row, False)
        
        # Update status bar
        self.statusBar().showMessage(f"Filter cleared. Showing all {self.packet_table.rowCount()} packets.")
        
    def apply_advanced_filter(self):
        """Apply advanced filter query to find specific packets"""
        try:
            query = self.advanced_filter_input.text().strip()
            if not query:
                self.clear_advanced_filter()
                return
                
            if not self.captured_packets:
                self.advanced_filter_status.setText("No packets captured yet.")
                return
                
            # Clear the results table
            self.advanced_filter_table.setRowCount(0)
            
            # Parse and apply the query
            matching_packets = []
            
            # Simple query parser
            try:
                # Count matches
                match_count = 0
                
                for i, packet in enumerate(self.captured_packets):
                    # Create a safe local environment with packet data
                    packet_env = packet.copy()
                    
                    # Evaluate the query against the packet
                    try:
                        # Use eval with restricted globals
                        result = eval(query, {"__builtins__": {}}, packet_env)
                        if result:
                            matching_packets.append((i, packet))
                            match_count += 1
                    except Exception as e:
                        # Skip packets that cause evaluation errors
                        continue
                
                # Display matching packets
                self.advanced_filter_table.setRowCount(len(matching_packets))
                
                for row, (packet_index, packet) in enumerate(matching_packets):
                    # Get color for this packet
                    bg_color = self.get_packet_color(packet)
                    
                    # Packet number
                    item = QTableWidgetItem(str(packet_index + 1))
                    item.setData(Qt.UserRole, packet_index)  # Store original index
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
                self.advanced_filter_status.setText(f"Found {match_count} matching packets out of {len(self.captured_packets)} total packets.")
                
                # Select first row if available
                if self.advanced_filter_table.rowCount() > 0:
                    self.advanced_filter_table.selectRow(0)
                
            except SyntaxError as e:
                self.advanced_filter_status.setText(f"Syntax error in query: {e}")
                return
                
        except Exception as e:
            logger.error(f"Error applying advanced filter: {e}")
            self.advanced_filter_status.setText(f"Error: {e}")
    
    def clear_advanced_filter(self):
        """Clear the advanced filter and show all packets"""
        self.advanced_filter_input.clear()
        self.advanced_filter_table.setRowCount(0)
        
        # Populate with all packets
        self.advanced_filter_table.setRowCount(len(self.captured_packets))
        
        for row, packet in enumerate(self.captured_packets):
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
        self.advanced_filter_status.setText(f"Showing all {len(self.captured_packets)} packets.")
        
    def on_advanced_filter_selection(self):
        """Handle selection in the advanced filter table"""
        selected_items = self.advanced_filter_table.selectedItems()
        if not selected_items:
            return
            
        # Get the row of the selected item
        row = selected_items[0].row()
        
        # Get the original packet index from the first column
        packet_index_item = self.advanced_filter_table.item(row, 0)
        if packet_index_item:
            packet_index = packet_index_item.data(Qt.UserRole)
            
            # Get the corresponding packet from the list
            if 0 <= packet_index < len(self.captured_packets):
                packet = self.captured_packets[packet_index]
                self.display_packet_details(packet)
                
                # Update status bar
                protocol = packet.get("protocol", "")
                if not protocol and "layers" in packet and packet["layers"]:
                    protocol = packet["layers"][-1]
                
                src = packet.get("src_ip", "")
                if "src_port" in packet and packet["src_port"]:
                    src += f":{packet['src_port']}"
                    
                dst = packet.get("dst_ip", "")
                if "dst_port" in packet and packet["dst_port"]:
                    dst += f":{packet['dst_port']}"
                    
                self.statusBar().showMessage(f"Selected: Packet #{packet_index+1} | {protocol} | {src} → {dst} | {packet.get('size', 0)} bytes")
                
    def show_color_legend(self):
        """Show a legend explaining the packet color coding"""
        try:
            legend_dialog = QDialog(self)
            legend_dialog.setWindowTitle("Packet Color Legend")
            legend_dialog.setMinimumSize(500, 400)
            
            layout = QVBoxLayout(legend_dialog)
            
            legend_text = QTextBrowser()
            legend_text.setOpenExternalLinks(False)
            legend_text.setHtml("""
            <h2>Packet Color Legend</h2>
            <p>Packets are color-coded based on protocol and port to help you quickly identify different types of traffic.</p>
            
            <table border="1" cellpadding="8" style="border-collapse: collapse; width: 100%;">
                <tr style="background-color: #f0f0f0;">
                    <th style="text-align: left;">Color</th>
                    <th style="text-align: left;">Protocol/Service</th>
                    <th style="text-align: left;">Description</th>
                </tr>
                <tr style="background-color: rgb(210, 230, 255);">
                    <td>Light Blue</td>
                    <td>HTTP</td>
                    <td>Web traffic (TCP port 80)</td>
                </tr>
                <tr style="background-color: rgb(180, 210, 255);">
                    <td>Medium Blue</td>
                    <td>HTTPS</td>
                    <td>Secure web traffic (TCP port 443)</td>
                </tr>
                <tr style="background-color: rgb(230, 210, 255);">
                    <td>Light Purple</td>
                    <td>DNS</td>
                    <td>Domain name resolution (UDP port 53)</td>
                </tr>
                <tr style="background-color: rgb(255, 255, 200);">
                    <td>Light Yellow</td>
                    <td>ICMP</td>
                    <td>Ping, traceroute, network errors</td>
                </tr>
                <tr style="background-color: rgb(210, 255, 210);">
                    <td>Light Green</td>
                    <td>ARP</td>
                    <td>Address Resolution Protocol</td>
                </tr>
                <tr style="background-color: rgb(255, 230, 200);">
                    <td>Light Orange</td>
                    <td>SSH</td>
                    <td>Secure Shell (TCP port 22)</td>
                </tr>
                <tr style="background-color: rgb(255, 200, 230);">
                    <td>Light Pink</td>
                    <td>FTP</td>
                    <td>File Transfer Protocol (TCP port 21)</td>
                </tr>
                <tr style="background-color: rgb(200, 255, 255);">
                    <td>Light Cyan</td>
                    <td>DHCP</td>
                    <td>Dynamic Host Configuration Protocol (UDP ports 67/68)</td>
                </tr>
                <tr style="background-color: rgb(240, 248, 255);">
                    <td>Very Light Blue</td>
                    <td>Other TCP</td>
                    <td>Other TCP traffic</td>
                </tr>
                <tr style="background-color: rgb(240, 255, 240);">
                    <td>Very Light Green</td>
                    <td>Other UDP</td>
                    <td>Other UDP traffic</td>
                </tr>
                <tr style="background-color: rgb(255, 200, 200);">
                    <td>Light Red</td>
                    <td>Error Packets</td>
                    <td>Packets with errors or warnings</td>
                </tr>
                <tr style="background-color: rgb(255, 255, 255);">
                    <td>White</td>
                    <td>Other</td>
                    <td>Other protocols</td>
                </tr>
            </table>
            """)
            
            close_button = QPushButton("Close")
            close_button.clicked.connect(legend_dialog.accept)
            close_button.setMinimumHeight(40)
            
            layout.addWidget(legend_text)
            layout.addWidget(close_button)
            
            legend_dialog.exec_()
            
        except Exception as e:
            logger.error(f"Error showing color legend: {e}")
            QMessageBox.warning(self, "Error", f"Could not show color legend: {e}")
    
    def show_advanced_filter_help(self):
        """Show help for advanced filter queries"""
        try:
            help_dialog = QDialog(self)
            help_dialog.setWindowTitle("Advanced Filter Help")
            help_dialog.setMinimumSize(700, 500)
            
            layout = QVBoxLayout(help_dialog)
            
            help_text = QTextBrowser()
            help_text.setOpenExternalLinks(True)
            help_text.setHtml("""
            <h2>Advanced Filter Query Syntax</h2>
            <p>The advanced filter allows you to search packets using Python expressions that evaluate to True or False.</p>
            
            <h3>Available Fields</h3>
            <p>You can filter on any field in the packet metadata, including:</p>
            <ul>
                <li><code>src_ip</code> - Source IP address</li>
                <li><code>dst_ip</code> - Destination IP address</li>
                <li><code>src_port</code> - Source port</li>
                <li><code>dst_port</code> - Destination port</li>
                <li><code>protocol</code> - Protocol name (e.g., "TCP", "UDP")</li>
                <li><code>size</code> - Packet size in bytes</li>
                <li><code>timestamp</code> - Packet timestamp</li>
                <li><code>layers</code> - List of protocol layers</li>
                <li><code>mac_src</code> - Source MAC address</li>
                <li><code>mac_dst</code> - Destination MAC address</li>
                <li><code>ttl</code> - Time to live</li>
                <li><code>dns</code> - DNS information (if present)</li>
                <li><code>http</code> - HTTP information (if present)</li>
            </ul>
            
            <h3>Query Examples</h3>
            <ul>
                <li><code>src_ip == '192.168.1.1'</code> - Packets from a specific IP</li>
                <li><code>dst_port == 80 or dst_port == 443</code> - HTTP or HTTPS traffic</li>
                <li><code>protocol == 'TCP' and size > 1000</code> - Large TCP packets</li>
                <li><code>'DNS' in layers</code> - DNS packets</li>
                <li><code>src_ip.startswith('10.0')</code> - Packets from 10.0.x.x subnet</li>
                <li><code>dst_ip.startswith('192.168') and dst_port == 22</code> - SSH to local network</li>
                <li><code>'HTTP' in layers and 'GET' in str(http)</code> - HTTP GET requests</li>
                <li><code>ttl < 64</code> - Packets with low TTL</li>
                <li><code>size > 1500</code> - Jumbo packets</li>
            </ul>
            
            <h3>Operators</h3>
            <ul>
                <li><code>==</code> - Equal to</li>
                <li><code>!=</code> - Not equal to</li>
                <li><code>&gt;</code> - Greater than</li>
                <li><code>&lt;</code> - Less than</li>
                <li><code>&gt;=</code> - Greater than or equal to</li>
                <li><code>&lt;=</code> - Less than or equal to</li>
                <li><code>and</code> - Logical AND</li>
                <li><code>or</code> - Logical OR</li>
                <li><code>not</code> - Logical NOT</li>
                <li><code>in</code> - Membership test</li>
            </ul>
            
            <h3>String Functions</h3>
            <p>You can use string methods like:</p>
            <ul>
                <li><code>startswith()</code> - Check if string starts with a prefix</li>
                <li><code>endswith()</code> - Check if string ends with a suffix</li>
                <li><code>contains()</code> - Check if string contains a substring</li>
            </ul>
            
            <h3>Notes</h3>
            <ul>
                <li>Queries are case-sensitive</li>
                <li>String values must be in quotes: <code>'192.168.1.1'</code> or <code>"192.168.1.1"</code></li>
                <li>Use <code>==</code> for equality comparison, not <code>=</code></li>
                <li>Some fields may not be present in all packets</li>
            </ul>
            """)
            
            close_button = QPushButton("Close")
            close_button.clicked.connect(help_dialog.accept)
            close_button.setMinimumHeight(40)
            
            layout.addWidget(help_text)
            layout.addWidget(close_button)
            
            help_dialog.exec_()
            
        except Exception as e:
            logger.error(f"Error showing advanced filter help: {e}")
            QMessageBox.warning(self, "Error", f"Could not show help: {e}")
    
    def show_filter_help(self):
        """Show comprehensive filter guide in a dedicated dialog"""
        try:
            # Create a dialog for the filter guide
            filter_guide_dialog = QDialog(self)
            filter_guide_dialog.setWindowTitle("Packet Filter Guide")
            filter_guide_dialog.setMinimumSize(800, 600)
            
            # Create layout
            layout = QVBoxLayout(filter_guide_dialog)
            
            # Create tab widget for different filter categories
            tabs = QTabWidget()
            
            # Create text browser for each tab
            basic_filters = QTextBrowser()
            advanced_filters = QTextBrowser()
            examples = QTextBrowser()
            operators = QTextBrowser()
            special_filters = QTextBrowser()
        except Exception as e:
            logger.error(f"Error creating filter help dialog: {e}")
            QMessageBox.warning(self, "Error", f"Could not create filter help dialog: {e}")
            return
        
        # Set larger font for better readability
        font = QFont(QApplication.font().family(), 12)
        basic_filters.setFont(font)
        advanced_filters.setFont(font)
        examples.setFont(font)
        operators.setFont(font)
        special_filters.setFont(font)
        
        # Add tabs
        tabs.addTab(basic_filters, "Basic Filters")
        tabs.addTab(advanced_filters, "Advanced Filters")
        tabs.addTab(operators, "Operators & Syntax")
        tabs.addTab(examples, "Examples")
        tabs.addTab(special_filters, "Special Filters")
        
        # Basic filters content
        basic_filters.setHtml("""
        <h2>Basic Protocol Filters</h2>
        <p>These filters show packets based on protocol type:</p>
        
        <table border="1" cellpadding="5" style="border-collapse: collapse; width: 100%;">
            <tr style="background-color: #f0f0f0;">
                <th style="text-align: left; width: 20%;">Filter</th>
                <th style="text-align: left;">Description</th>
            </tr>
            <tr>
                <td><code>tcp</code></td>
                <td>Show only TCP packets</td>
            </tr>
            <tr>
                <td><code>udp</code></td>
                <td>Show only UDP packets</td>
            </tr>
            <tr>
                <td><code>icmp</code></td>
                <td>Show only ICMP packets</td>
            </tr>
            <tr>
                <td><code>arp</code></td>
                <td>Show only ARP packets</td>
            </tr>
            <tr>
                <td><code>dns</code></td>
                <td>Show only DNS packets</td>
            </tr>
            <tr>
                <td><code>http</code></td>
                <td>Show only HTTP packets</td>
            </tr>
            <tr>
                <td><code>ip</code></td>
                <td>Show only IPv4 packets</td>
            </tr>
            <tr>
                <td><code>ip6</code></td>
                <td>Show only IPv6 packets</td>
            </tr>
        </table>
        
        <h2>Host & Network Filters</h2>
        <p>These filters show packets based on IP addresses:</p>
        
        <table border="1" cellpadding="5" style="border-collapse: collapse; width: 100%;">
            <tr style="background-color: #f0f0f0;">
                <th style="text-align: left; width: 40%;">Filter</th>
                <th style="text-align: left;">Description</th>
            </tr>
            <tr>
                <td><code>host 192.168.1.1</code></td>
                <td>Show packets with this IP as source or destination</td>
            </tr>
            <tr>
                <td><code>src host 192.168.1.1</code></td>
                <td>Show packets with this IP as source</td>
            </tr>
            <tr>
                <td><code>dst host 192.168.1.1</code></td>
                <td>Show packets with this IP as destination</td>
            </tr>
            <tr>
                <td><code>net 192.168.0.0/24</code></td>
                <td>Show packets in this network range</td>
            </tr>
        </table>
        
        <h2>Port Filters</h2>
        <p>These filters show packets based on port numbers:</p>
        
        <table border="1" cellpadding="5" style="border-collapse: collapse; width: 100%;">
            <tr style="background-color: #f0f0f0;">
                <th style="text-align: left; width: 30%;">Filter</th>
                <th style="text-align: left;">Description</th>
            </tr>
            <tr>
                <td><code>port 80</code></td>
                <td>Show packets with this port as source or destination</td>
            </tr>
            <tr>
                <td><code>src port 80</code></td>
                <td>Show packets with this port as source</td>
            </tr>
            <tr>
                <td><code>dst port 80</code></td>
                <td>Show packets with this port as destination</td>
            </tr>
            <tr>
                <td><code>port 1000-2000</code></td>
                <td>Show packets with ports in this range</td>
            </tr>
        </table>
        """)
        
        # Advanced filters content
        advanced_filters.setHtml("""
        <h2>Advanced Protocol Filters</h2>
        <p>These filters allow for more specific protocol filtering:</p>
        
        <table border="1" cellpadding="5" style="border-collapse: collapse; width: 100%;">
            <tr style="background-color: #f0f0f0;">
                <th style="text-align: left; width: 40%;">Filter</th>
                <th style="text-align: left;">Description</th>
            </tr>
            <tr>
                <td><code>tcp[tcpflags] & (tcp-syn|tcp-fin) != 0</code></td>
                <td>Show TCP packets with SYN or FIN flags set</td>
            </tr>
            <tr>
                <td><code>tcp[tcpflags] & tcp-syn != 0</code></td>
                <td>Show only TCP SYN packets</td>
            </tr>
            <tr>
                <td><code>tcp[tcpflags] & tcp-ack != 0</code></td>
                <td>Show only TCP ACK packets</td>
            </tr>
            <tr>
                <td><code>tcp[tcpflags] & tcp-rst != 0</code></td>
                <td>Show only TCP RST packets</td>
            </tr>
            <tr>
                <td><code>tcp[tcpflags] & tcp-push != 0</code></td>
                <td>Show only TCP PSH packets</td>
            </tr>
            <tr>
                <td><code>tcp[2:2] = 80</code></td>
                <td>Show packets with destination port 80 (HTTP)</td>
            </tr>
            <tr>
                <td><code>tcp[0:2] = 80</code></td>
                <td>Show packets with source port 80</td>
            </tr>
            <tr>
                <td><code>ether host 00:11:22:33:44:55</code></td>
                <td>Show packets with this MAC address</td>
            </tr>
            <tr>
                <td><code>ip[8] = 1</code></td>
                <td>Show packets with TTL=1</td>
            </tr>
            <tr>
                <td><code>greater 1000</code></td>
                <td>Show packets larger than 1000 bytes</td>
            </tr>
            <tr>
                <td><code>less 128</code></td>
                <td>Show packets smaller than 128 bytes</td>
            </tr>
        </table>
        
        <h2>Application Layer Filters</h2>
        <p>These filters target application-layer protocols:</p>
        
        <table border="1" cellpadding="5" style="border-collapse: collapse; width: 100%;">
            <tr style="background-color: #f0f0f0;">
                <th style="text-align: left; width: 30%;">Filter</th>
                <th style="text-align: left;">Description</th>
            </tr>
            <tr>
                <td><code>http.request</code></td>
                <td>Show HTTP request packets</td>
            </tr>
            <tr>
                <td><code>http.response</code></td>
                <td>Show HTTP response packets</td>
            </tr>
            <tr>
                <td><code>dns.qry.name contains "example"</code></td>
                <td>Show DNS queries containing "example"</td>
            </tr>
            <tr>
                <td><code>dns.resp.type == 1</code></td>
                <td>Show DNS responses with A records</td>
            </tr>
        </table>
        """)
        
        # Operators content
        operators.setHtml("""
        <h2>Logical Operators</h2>
        <p>These operators allow you to combine multiple filter conditions:</p>
        
        <table border="1" cellpadding="5" style="border-collapse: collapse; width: 100%;">
            <tr style="background-color: #f0f0f0;">
                <th style="text-align: left; width: 20%;">Operator</th>
                <th style="text-align: left;">Description</th>
                <th style="text-align: left;">Example</th>
            </tr>
            <tr>
                <td><code>and</code> or <code>&&</code></td>
                <td>Logical AND - both conditions must be true</td>
                <td><code>tcp and port 80</code></td>
            </tr>
            <tr>
                <td><code>or</code> or <code>||</code></td>
                <td>Logical OR - either condition can be true</td>
                <td><code>tcp or udp</code></td>
            </tr>
            <tr>
                <td><code>not</code> or <code>!</code></td>
                <td>Logical NOT - negate the condition</td>
                <td><code>not icmp</code> or <code>!icmp</code></td>
            </tr>
            <tr>
                <td><code>==</code> or <code>=</code></td>
                <td>Equal to</td>
                <td><code>ip[8] == 64</code></td>
            </tr>
            <tr>
                <td><code>!=</code></td>
                <td>Not equal to</td>
                <td><code>tcp[tcpflags] != 0</code></td>
            </tr>
            <tr>
                <td><code>&gt;</code></td>
                <td>Greater than</td>
                <td><code>ip[8] > 1</code></td>
            </tr>
            <tr>
                <td><code>&lt;</code></td>
                <td>Less than</td>
                <td><code>ip[8] < 255</code></td>
            </tr>
            <tr>
                <td><code>&gt;=</code></td>
                <td>Greater than or equal to</td>
                <td><code>tcp[0:2] >= 1024</code></td>
            </tr>
            <tr>
                <td><code>&lt;=</code></td>
                <td>Less than or equal to</td>
                <td><code>tcp[0:2] <= 1023</code></td>
            </tr>
        </table>
        
        <h2>Grouping with Parentheses</h2>
        <p>Use parentheses to group expressions and control precedence:</p>
        
        <pre>
        (tcp or udp) and port 80
        host 192.168.1.1 and (tcp or icmp)
        </pre>
        
        <h2>Byte Offset Syntax</h2>
        <p>Access specific bytes in packet headers:</p>
        
        <pre>
        proto[offset:size]
        </pre>
        
        <p>Where:</p>
        <ul>
            <li><code>proto</code> is the protocol (ip, tcp, udp, etc.)</li>
            <li><code>offset</code> is the byte offset from the start of the header</li>
            <li><code>size</code> is the number of bytes to examine (1, 2, or 4)</li>
        </ul>
        
        <p>Examples:</p>
        <pre>
        ip[0] & 0xf0 = 0x40   # IPv4 packets
        tcp[13] & 0x02 != 0   # TCP SYN flag
        </pre>
        """)
        
        # Examples content
        examples.setHtml("""
        <h2>Common Filter Examples</h2>
        <p>Here are some practical examples of packet filters:</p>
        
        <table border="1" cellpadding="5" style="border-collapse: collapse; width: 100%;">
            <tr style="background-color: #f0f0f0;">
                <th style="text-align: left;">Filter Expression</th>
                <th style="text-align: left;">Description</th>
            </tr>
            <tr>
                <td><code>tcp port 80 or tcp port 443</code></td>
                <td>Show HTTP or HTTPS traffic</td>
            </tr>
            <tr>
                <td><code>host 192.168.1.1 and not (port 22 or port 23)</code></td>
                <td>Show traffic to/from 192.168.1.1 except SSH and Telnet</td>
            </tr>
            <tr>
                <td><code>tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 and not tcp[tcpflags] & (tcp-ack) != 0</code></td>
                <td>Show TCP SYN or FIN packets without the ACK flag (potential scan)</td>
            </tr>
            <tr>
                <td><code>tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)</code></td>
                <td>Show HTTP GET or POST requests</td>
            </tr>
            <tr>
                <td><code>icmp[icmptype] = icmp-echo or icmp[icmptype] = icmp-echoreply</code></td>
                <td>Show ICMP ping requests and replies</td>
            </tr>
            <tr>
                <td><code>ether broadcast or ip broadcast</code></td>
                <td>Show broadcast traffic</td>
            </tr>
            <tr>
                <td><code>ether multicast or ip multicast</code></td>
                <td>Show multicast traffic</td>
            </tr>
            <tr>
                <td><code>ip[6:2] & 0x1fff != 0</code></td>
                <td>Show fragmented IP packets</td>
            </tr>
            <tr>
                <td><code>ip[8] < 10</code></td>
                <td>Show packets with TTL less than 10</td>
            </tr>
            <tr>
                <td><code>tcp[2:2] >= 1024 and tcp[0:2] >= 1024</code></td>
                <td>Show traffic between ephemeral ports (non-server ports)</td>
            </tr>
        </table>
        
        <h2>Troubleshooting Examples</h2>
        <p>Filters useful for network troubleshooting:</p>
        
        <table border="1" cellpadding="5" style="border-collapse: collapse; width: 100%;">
            <tr style="background-color: #f0f0f0;">
                <th style="text-align: left;">Filter Expression</th>
                <th style="text-align: left;">Use Case</th>
            </tr>
            <tr>
                <td><code>tcp[tcpflags] & tcp-rst != 0</code></td>
                <td>Find connection resets that might indicate service problems</td>
            </tr>
            <tr>
                <td><code>tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0</code></td>
                <td>Find unanswered connection attempts</td>
            </tr>
            <tr>
                <td><code>icmp[icmptype] = icmp-unreach</code></td>
                <td>Find ICMP "destination unreachable" messages</td>
            </tr>
            <tr>
                <td><code>greater 1500</code></td>
                <td>Find packets larger than typical MTU (potential fragmentation issues)</td>
            </tr>
            <tr>
                <td><code>arp and arp[6:2] = 2</code></td>
                <td>Find ARP replies (useful for IP conflict detection)</td>
            </tr>
        </table>
        """)
        
        # Special filters content
        special_filters.setHtml("""
        <h2>Special Filter Expressions</h2>
        <p>These filters provide additional functionality:</p>
        
        <table border="1" cellpadding="5" style="border-collapse: collapse; width: 100%;">
            <tr style="background-color: #f0f0f0;">
                <th style="text-align: left; width: 30%;">Filter</th>
                <th style="text-align: left;">Description</th>
            </tr>
            <tr>
                <td><code>vlan</code></td>
                <td>Show only VLAN-tagged traffic</td>
            </tr>
            <tr>
                <td><code>vlan 100</code></td>
                <td>Show traffic on VLAN 100</td>
            </tr>
            <tr>
                <td><code>mpls</code></td>
                <td>Show only MPLS traffic</td>
            </tr>
            <tr>
                <td><code>pppoed</code></td>
                <td>Show PPPoE discovery packets</td>
            </tr>
            <tr>
                <td><code>pppoes</code></td>
                <td>Show PPPoE session packets</td>
            </tr>
            <tr>
                <td><code>geneve</code></td>
                <td>Show GENEVE encapsulated packets</td>
            </tr>
            <tr>
                <td><code>vxlan</code></td>
                <td>Show VXLAN encapsulated packets</td>
            </tr>
            <tr>
                <td><code>tcp port 179</code></td>
                <td>Show BGP traffic</td>
            </tr>
            <tr>
                <td><code>tcp port 389</code></td>
                <td>Show LDAP traffic</td>
            </tr>
            <tr>
                <td><code>tcp port 445</code></td>
                <td>Show SMB traffic</td>
            </tr>
        </table>
        
        <h2>Filter Optimization Tips</h2>
        <p>For better performance when filtering large captures:</p>
        
        <ul>
            <li>Start with the most specific filter that will eliminate the most packets</li>
            <li>Use protocol filters before content filters</li>
            <li>Avoid complex regular expressions when possible</li>
            <li>Use host/port filters before examining packet contents</li>
            <li>When using multiple OR conditions, group similar filters together</li>
        </ul>
        
        <h2>Saving Filters</h2>
        <p>You can save frequently used filters for quick access:</p>
        
        <ol>
            <li>Enter your filter expression in the filter box</li>
            <li>Click the "Save" button next to the filter box</li>
            <li>Enter a name for your filter</li>
            <li>Access saved filters from the dropdown menu</li>
        </ol>
        """)
        
        # Add close button
        close_button = QPushButton("Close")
        close_button.setMinimumHeight(40)
        close_button.setFont(QFont(QApplication.font().family(), 12))
        close_button.clicked.connect(filter_guide_dialog.accept)
        
        # Add widgets to layout
        layout.addWidget(tabs)
        layout.addWidget(close_button)
        
        try:
            # Show the dialog
            filter_guide_dialog.exec_()
        except Exception as e:
            logger.error(f"Error displaying filter help dialog: {e}")
            QMessageBox.warning(self, "Error", f"Could not display filter help: {e}")
    
    def update_protocol_stats(self, packet):
        """Update protocol statistics based on packet"""
        # Get protocol
        protocol = packet.get("protocol", "")
        if not protocol and "layers" in packet and packet["layers"]:
            protocol = packet["layers"][-1]  # Use highest layer
        
        # Update protocol counters
        if protocol == "TCP":
            self.protocol_stats["tcp_packets"] += 1
        elif protocol == "UDP":
            self.protocol_stats["udp_packets"] += 1
        elif protocol == "ICMP":
            self.protocol_stats["icmp_packets"] += 1
        elif protocol == "ARP":
            self.protocol_stats["arp_packets"] += 1
        else:
            self.protocol_stats["other_packets"] += 1
        
        # Check for application protocols
        if "DNS" in packet.get("layers", []):
            self.protocol_stats["dns_packets"] += 1
        if "HTTP" in packet.get("layers", []):
            self.protocol_stats["http_packets"] += 1
        
        # Update status bar labels
        self.tcp_label.setText(f"TCP: {self.protocol_stats['tcp_packets']:,}")
        self.udp_label.setText(f"UDP: {self.protocol_stats['udp_packets']:,}")
        self.icmp_label.setText(f"ICMP: {self.protocol_stats['icmp_packets']:,}")
        self.other_label.setText(f"Other: {self.protocol_stats['other_packets']:,}")
    
    def clear_display(self):
        """Clear all captured packets from the display"""
        if not self.captured_packets:
            return
        
        reply = QMessageBox.question(
            self, "Clear Display",
            f"Are you sure you want to clear {len(self.captured_packets)} packets from the display?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Clear packet table
            self.packet_table.setRowCount(0)
            
            # Clear packet details
            self.packet_tree.clear()
            self.hex_view.clear()
            self.raw_view.clear()
            self.summary_view.clear()
            
            # Clear advanced filter
            self.advanced_filter_table.setRowCount(0)
            self.advanced_filter_status.setText("No packets captured yet.")
            self.advanced_filter_input.clear()
            
            # Clear packet list
            self.captured_packets = []
            
            # Reset protocol statistics
            for key in self.protocol_stats:
                self.protocol_stats[key] = 0
            
            # Update status labels
            self.tcp_label.setText("TCP: 0")
            self.udp_label.setText("UDP: 0")
            self.icmp_label.setText("ICMP: 0")
            self.other_label.setText("Other: 0")
            
            # Update UI
            self.setWindowTitle("PyGuard Desktop - 0 packets captured")
            self.statusBar().showMessage("Display cleared")
            logger.info("Display cleared")
    
    def set_packet_limit(self, limit_text):
        """Set the maximum number of packets to display"""
        try:
            if limit_text == "Unlimited":
                self.max_display_packets = float('inf')
                self.statusBar().showMessage(f"Packet display limit set to unlimited. All packets will be kept.")
            else:
                # Extract the number part and parse it (remove commas)
                limit_number = limit_text.split(" ")[0]
                limit = int(limit_number.replace(",", ""))
                self.max_display_packets = limit
                
                # Show a more informative message
                if self.max_display_packets < len(self.captured_packets):
                    # We already have more packets than the new limit
                    excess = len(self.captured_packets) - self.max_display_packets
                    self.statusBar().showMessage(
                        f"Packet display limit set to {limit_number}. {excess:,} oldest packets will be removed on next update."
                    )
                else:
                    self.statusBar().showMessage(
                        f"Packet display limit set to {limit_number}. Older packets will be removed when this limit is reached."
                    )
            
            logger.info(f"Packet display limit set to {limit_text}")
        except Exception as e:
            logger.error(f"Error setting packet limit: {e}")
            self.max_display_packets = 100000  # Default
    
    def handle_error(self, error_message):
        """Handle errors from the capture thread"""
        logger.error(f"Capture error: {error_message}")
        self.statusBar().showMessage(f"Error: {error_message}")
        
        # Reset UI
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_label.setText("Error")
        
        # Show error message
        QMessageBox.critical(self, "Capture Error", error_message)
    
    def _format_packet(self, metadata):
        """Format packet metadata for display"""
        # Basic packet info
        packet_str = f"--- Packet captured at {metadata['timestamp']} ---\n"
        packet_str += f"Protocol: {metadata['protocol']}\n"
        
        # IP information
        packet_str += f"Source IP: {metadata['src_ip']}"
        if metadata['src_port']:
            packet_str += f":{metadata['src_port']}"
        packet_str += "\n"
        
        packet_str += f"Destination IP: {metadata['dst_ip']}"
        if metadata['dst_port']:
            packet_str += f":{metadata['dst_port']}"
        packet_str += "\n"
        
        # Size information
        packet_str += f"Size: {metadata['size']} bytes\n"
        
        # Protocol-specific information
        if metadata['protocol'] == "TCP" and 'tcp_flags' in metadata:
            packet_str += f"TCP Flags: {', '.join(metadata['tcp_flags'])}\n"
        
        elif metadata['protocol'] == "ICMP" and 'icmp_type' in metadata:
            packet_str += f"ICMP Type: {metadata['icmp_type']}, Code: {metadata['icmp_code']}\n"
        
        packet_str += "\n"
        return packet_str
    
    def save_packets(self):
        """Save captured packets to a file"""
        if not self.captured_packets:
            QMessageBox.warning(self, "No Packets", "No packets to save.")
            return
            
        # Check if we have a large number of packets
        packet_count = len(self.captured_packets)
        if packet_count > 10000:
            confirm = QMessageBox.question(
                self, "Large Capture",
                f"You are about to save {packet_count:,} packets, which may take some time. Continue?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
            )
            if confirm != QMessageBox.Yes:
                return
        
        # Ask for file name and format
        file_dialog = QFileDialog()
        file_dialog.setAcceptMode(QFileDialog.AcceptSave)
        file_dialog.setNameFilter("PCAP files (*.pcap);;JSON files (*.json);;CSV files (*.csv)")
        file_dialog.setDefaultSuffix("pcap")
        
        if not file_dialog.exec_():
            return
        
        file_path = file_dialog.selectedFiles()[0]
        selected_filter = file_dialog.selectedNameFilter()
        
        # Create progress dialog for large captures
        progress = QProgressDialog("Saving packets...", "Cancel", 0, packet_count, self)
        progress.setWindowTitle("Saving Packets")
        progress.setWindowModality(Qt.WindowModal)
        progress.setMinimumDuration(500)  # Only show for operations taking > 500ms
        
        try:
            packet_count = len(self.captured_packets)
            
            if "pcap" in selected_filter:
                # Save as PCAP file
                from scapy.all import wrpcap
                
                # Check if we have raw packet data
                if 'packet_data' in self.captured_packets[0]:
                    # For PCAP files, we need to collect all packet data first
                    progress.setLabelText("Preparing packet data for PCAP...")
                    QApplication.processEvents()
                    
                    # Get all packet data
                    packet_data_list = []
                    for i, p in enumerate(self.captured_packets):
                        if 'packet_data' in p:
                            packet_data_list.append(p['packet_data'])
                        
                        # Update progress every 100 packets
                        if i % 100 == 0:
                            progress.setValue(i)
                            QApplication.processEvents()
                            
                            # Check for cancel
                            if progress.wasCanceled():
                                logger.info("PCAP save canceled by user")
                                return
                    
                    # Write PCAP file
                    progress.setLabelText("Writing PCAP file...")
                    QApplication.processEvents()
                    wrpcap(file_path, packet_data_list)
                    logger.info(f"Saved {len(packet_data_list)} packets to PCAP file: {file_path}")
                else:
                    # We don't have raw packet data, show error
                    progress.close()
                    QMessageBox.warning(self, "Cannot Save PCAP", 
                                       "Cannot save as PCAP because raw packet data is not available. Try JSON format instead.")
                    return
            
            elif "json" in selected_filter:
                # Save as JSON file
                import json
                
                # Convert packets to serializable format
                progress.setLabelText("Converting packets to JSON format...")
                serializable_packets = []
                
                for i, packet in enumerate(self.captured_packets):
                    # Create a copy of the packet dict
                    packet_copy = {}
                    for key, value in packet.items():
                        # Skip binary data and complex objects
                        if key not in ['packet_data', 'scapy_packet']:
                            packet_copy[key] = value
                    serializable_packets.append(packet_copy)
                    
                    # Update progress every 100 packets
                    if i % 100 == 0:
                        progress.setValue(i)
                        QApplication.processEvents()
                        
                        # Check for cancel
                        if progress.wasCanceled():
                            logger.info("JSON save canceled by user")
                            return
                
                # Write JSON file
                progress.setLabelText("Writing JSON file...")
                QApplication.processEvents()
                with open(file_path, 'w') as f:
                    json.dump(serializable_packets, f, indent=2)
                
                logger.info(f"Saved {len(serializable_packets)} packets to JSON file: {file_path}")
            
            elif "csv" in selected_filter:
                # Save as CSV file
                import csv
                
                # Define CSV fields
                fields = ['frame_number', 'timestamp', 'src_ip', 'src_port', 
                         'dst_ip', 'dst_port', 'protocol', 'size', 'summary']
                
                with open(file_path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
                    writer.writeheader()
                    
                    for i, packet in enumerate(self.captured_packets):
                        # Create a clean row with only simple values
                        row = {}
                        for field in fields:
                            if field in packet:
                                # Convert complex objects to strings
                                if isinstance(packet[field], (dict, list)):
                                    row[field] = str(packet[field])
                                else:
                                    row[field] = packet[field]
                            elif field == 'frame_number' and 'frame_number' not in packet:
                                # Add frame number if not present
                                row[field] = i + 1
                        
                        writer.writerow(row)
                        
                        # Update progress every 100 packets
                        if i % 100 == 0:
                            progress.setValue(i)
                            QApplication.processEvents()
                            
                            # Check for cancel
                            if progress.wasCanceled():
                                logger.info("CSV save canceled by user")
                                return
                
                logger.info(f"Saved {len(self.captured_packets)} packets to CSV file: {file_path}")
            
            # Set progress to 100%
            progress.setValue(packet_count)
            
            QMessageBox.information(self, "Save Complete", f"Saved {packet_count} packets to {file_path}")
        
        except Exception as e:
            logger.error(f"Error saving packets: {e}")
            QMessageBox.critical(self, "Save Error", f"Error saving packets: {e}")
        finally:
            # Make sure progress dialog is closed
            progress.close()
    
    def save_ui_state(self):
        """Save UI state including splitter positions"""
        try:
            settings = QSettings("PyGuard", "DesktopApp")
            
            # Save window geometry
            settings.setValue("geometry", self.saveGeometry())
            
            # Save splitter states
            settings.setValue("main_splitter", self.main_splitter.saveState())
            settings.setValue("details_splitter", self.details_splitter.saveState())
            settings.setValue("horizontal_details_splitter", self.horizontal_details_splitter.saveState())
            
            # Save splitter sizes
            settings.setValue("main_splitter_sizes", self.main_splitter.sizes())
            settings.setValue("details_splitter_sizes", self.details_splitter.sizes())
            settings.setValue("horizontal_details_splitter_sizes", self.horizontal_details_splitter.sizes())
            
            # Save active tab indexes
            settings.setValue("details_tab_index", self.details_tabs.currentIndex())
            settings.setValue("secondary_tab_index", self.secondary_tabs.currentIndex())
            
            logger.info("UI state saved")
        except Exception as e:
            logger.error(f"Error saving UI state: {e}")
    
    def load_ui_state(self):
        """Load UI state including splitter positions"""
        try:
            settings = QSettings("PyGuard", "DesktopApp")
            
            # Restore window geometry if available
            geometry = settings.value("geometry")
            if geometry:
                self.restoreGeometry(geometry)
            
            # Restore main splitter state if available
            main_splitter_state = settings.value("main_splitter")
            if main_splitter_state:
                self.main_splitter.restoreState(main_splitter_state)
            else:
                # Default sizes if no saved state
                self.main_splitter.setSizes([500, 500])
            
            # Restore details splitter state if available
            details_splitter_state = settings.value("details_splitter")
            if details_splitter_state:
                self.details_splitter.restoreState(details_splitter_state)
            else:
                # Default sizes if no saved state
                self.details_splitter.setSizes([450, 50])
                
            # Restore horizontal details splitter state if available
            horizontal_details_splitter_state = settings.value("horizontal_details_splitter")
            if horizontal_details_splitter_state:
                self.horizontal_details_splitter.restoreState(horizontal_details_splitter_state)
            else:
                # Default sizes if no saved state
                self.horizontal_details_splitter.setSizes([400, 400])
            
            # Alternative: restore from saved sizes
            main_sizes = settings.value("main_splitter_sizes")
            if main_sizes and not main_splitter_state:
                self.main_splitter.setSizes(main_sizes)
                
            details_sizes = settings.value("details_splitter_sizes")
            if details_sizes and not details_splitter_state:
                self.details_splitter.setSizes(details_sizes)
                
            horizontal_details_sizes = settings.value("horizontal_details_splitter_sizes")
            if horizontal_details_sizes and not horizontal_details_splitter_state:
                self.horizontal_details_splitter.setSizes(horizontal_details_sizes)
                
            # Restore active tab indexes
            details_tab_index = settings.value("details_tab_index")
            if details_tab_index is not None:
                self.details_tabs.setCurrentIndex(int(details_tab_index))
                
            secondary_tab_index = settings.value("secondary_tab_index")
            if secondary_tab_index is not None:
                self.secondary_tabs.setCurrentIndex(int(secondary_tab_index))
                
            logger.info("UI state loaded")
        except Exception as e:
            logger.error(f"Error loading UI state: {e}")
            # Set default sizes if loading fails
            self.main_splitter.setSizes([500, 500])
            self.details_splitter.setSizes([450, 50])
            self.horizontal_details_splitter.setSizes([400, 400])
    
    def closeEvent(self, event):
        """Handle window close event"""
        # Save UI state before potentially closing
        self.save_ui_state()
        
        # Stop capture if running
        if self.capture_thread and self.capture_thread.isRunning():
            reply = QMessageBox.question(
                self, "Confirm Exit",
                "Capture is still running. Stop capture and exit?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.stop_capture()
                
                # Ask if user wants to save captured packets
                if self.captured_packets:
                    save_reply = QMessageBox.question(
                        self, "Save Packets",
                        f"Do you want to save {len(self.captured_packets)} captured packets?",
                        QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
                    )
                    
                    if save_reply == QMessageBox.Yes:
                        self.save_packets()
                
                event.accept()
            else:
                event.ignore()
        else:
            # Ask if user wants to save captured packets
            if self.captured_packets:
                save_reply = QMessageBox.question(
                    self, "Save Packets",
                    f"Do you want to save {len(self.captured_packets)} captured packets?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
                )
                
                if save_reply == QMessageBox.Yes:
                    self.save_packets()
            
            event.accept()

class LogHandler(logging.Handler):
    """Custom log handler to display logs in the UI"""
    
    def __init__(self, text_edit):
        super().__init__()
        self.text_edit = text_edit
        self.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    def emit(self, record):
        """Emit a log record"""
        msg = self.format(record)
        self.text_edit.append(msg)
        # Scroll to bottom
        cursor = self.text_edit.textCursor()
        cursor.movePosition(cursor.End)
        self.text_edit.setTextCursor(cursor)

def main():
    """Main entry point for the desktop application"""
    app = QApplication(sys.argv)
    window = DesktopApp()
    window.show()
    return app.exec_()

if __name__ == "__main__":
    sys.exit(main())