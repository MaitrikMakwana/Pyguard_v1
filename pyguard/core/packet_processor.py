"""
Packet processor module for extracting metadata from captured packets
with deep protocol inspection capabilities
"""

import logging
import time
import json
from datetime import datetime
import socket
import struct
import base64
from scapy.all import (
    IP, IPv6, TCP, UDP, ICMP, ICMPv6, ARP, DNS, 
    Raw, Ether, HTTPRequest, HTTPResponse, DNSQR, DNSRR,
    BOOTP, DHCP, NTP, SNMP, SMTP, FTP, Dot11, Dot1Q
)
from scapy.layers.http import HTTP
from scapy.layers.tls import TLS
from scapy.layers.inet import IPerror, TCPerror, UDPerror, ICMPerror
from scapy.layers.dhcp import DHCP_am
from scapy.packet import Packet

logger = logging.getLogger(__name__)

class PacketProcessor:
    """Extract metadata from network packets with deep protocol inspection"""
    
    def __init__(self, config):
        """Initialize packet processor with configuration"""
        self.config = config
        self.deep_inspection = config.capture.get("deep_inspection", True)
        self.extract_payload = config.capture.get("extract_payload", False)
        self.enabled_protocols = config.protocols
        self.packet_count = 0
        self.sampling_rate = config.capture.get("sampling_rate", 1.0)
    
    def process_packet(self, header, packet):
        """Process a packet and extract metadata"""
        try:
            # Apply packet sampling if configured
            self.packet_count += 1
            if self.sampling_rate < 1.0 and (self.packet_count % int(1/self.sampling_rate) != 0):
                return None  # Skip this packet based on sampling rate
            
            # Extract timestamp from header
            timestamp = header.getts()
            ts_sec = timestamp[0]
            ts_usec = timestamp[1]
            
            # Create timestamp as datetime object
            packet_time = datetime.fromtimestamp(ts_sec + ts_usec / 1000000)
            
            # Initialize metadata dictionary
            metadata = {
                "timestamp": packet_time.isoformat(),
                "timestamp_epoch": ts_sec + ts_usec / 1000000,
                "capture_length": header.getcaplen(),
                "packet_length": header.getlen(),
                "layers": []  # Track all layers found in the packet
            }
            
            # Extract Ethernet layer metadata
            if Ether in packet and self.enabled_protocols.get("ethernet", True):
                metadata.update(self._extract_ethernet_metadata(packet[Ether]))
                metadata["layers"].append("Ethernet")
            
            # Check for VLAN tagging
            if Dot1Q in packet:
                metadata.update(self._extract_vlan_metadata(packet[Dot1Q]))
                metadata["layers"].append("VLAN")
            
            # Extract IP layer metadata
            if IP in packet and self.enabled_protocols.get("ip", True):
                metadata.update(self._extract_ipv4_metadata(packet[IP]))
                # Determine packet direction
                metadata["direction"] = self._determine_direction(metadata["src_ip"])
                metadata["layers"].append("IPv4")
            elif IPv6 in packet and self.enabled_protocols.get("ip", True):
                metadata.update(self._extract_ipv6_metadata(packet[IPv6]))
                # Determine packet direction
                metadata["direction"] = self._determine_direction(metadata["src_ip"])
                metadata["layers"].append("IPv6")
            
            # Extract transport layer metadata
            if TCP in packet and self.enabled_protocols.get("tcp", True):
                metadata.update(self._extract_tcp_metadata(packet[TCP]))
                metadata["layers"].append("TCP")
            elif UDP in packet and self.enabled_protocols.get("udp", True):
                metadata.update(self._extract_udp_metadata(packet[UDP]))
                metadata["layers"].append("UDP")
            elif ICMP in packet and self.enabled_protocols.get("icmp", True):
                metadata.update(self._extract_icmp_metadata(packet[ICMP]))
                metadata["layers"].append("ICMP")
            elif ICMPv6 in packet and self.enabled_protocols.get("icmp", True):
                metadata.update(self._extract_icmpv6_metadata(packet[ICMPv6]))
                metadata["layers"].append("ICMPv6")
            elif ARP in packet and self.enabled_protocols.get("arp", True):
                metadata.update(self._extract_arp_metadata(packet[ARP]))
                metadata["layers"].append("ARP")
            
            # Extract application layer metadata
            if DNS in packet and self.enabled_protocols.get("dns", True):
                metadata.update(self._extract_dns_metadata(packet[DNS]))
                metadata["layers"].append("DNS")
            
            # Extract HTTP metadata if present
            if TCP in packet and self.enabled_protocols.get("http", True):
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    http_metadata = self._extract_http_metadata(packet)
                    if http_metadata:
                        metadata.update(http_metadata)
                        metadata["layers"].append("HTTP")
            
            # Extract HTTPS/TLS metadata if present
            if TCP in packet and self.enabled_protocols.get("tls", True):
                if packet[TCP].dport == 443 or packet[TCP].sport == 443 or TLS in packet:
                    tls_metadata = self._extract_tls_metadata(packet)
                    if tls_metadata:
                        metadata.update(tls_metadata)
                        metadata["layers"].append("TLS")
            
            # Extract DHCP metadata if present
            if UDP in packet and self.enabled_protocols.get("dhcp", True):
                if packet[UDP].dport == 67 or packet[UDP].dport == 68 or DHCP in packet or BOOTP in packet:
                    dhcp_metadata = self._extract_dhcp_metadata(packet)
                    if dhcp_metadata:
                        metadata.update(dhcp_metadata)
                        metadata["layers"].append("DHCP")
            
            # Extract NTP metadata if present
            if UDP in packet and self.enabled_protocols.get("ntp", True):
                if packet[UDP].dport == 123 or packet[UDP].sport == 123 or NTP in packet:
                    ntp_metadata = self._extract_ntp_metadata(packet)
                    if ntp_metadata:
                        metadata.update(ntp_metadata)
                        metadata["layers"].append("NTP")
            
            # Extract SMTP metadata if present
            if TCP in packet and self.enabled_protocols.get("smtp", True):
                if packet[TCP].dport == 25 or packet[TCP].sport == 25 or SMTP in packet:
                    smtp_metadata = self._extract_smtp_metadata(packet)
                    if smtp_metadata:
                        metadata.update(smtp_metadata)
                        metadata["layers"].append("SMTP")
            
            # Extract FTP metadata if present
            if TCP in packet and self.enabled_protocols.get("ftp", True):
                if packet[TCP].dport == 21 or packet[TCP].sport == 21 or FTP in packet:
                    ftp_metadata = self._extract_ftp_metadata(packet)
                    if ftp_metadata:
                        metadata.update(ftp_metadata)
                        metadata["layers"].append("FTP")
            
            # Extract SNMP metadata if present
            if UDP in packet and self.enabled_protocols.get("snmp", True):
                if packet[UDP].dport == 161 or packet[UDP].sport == 161 or SNMP in packet:
                    snmp_metadata = self._extract_snmp_metadata(packet)
                    if snmp_metadata:
                        metadata.update(snmp_metadata)
                        metadata["layers"].append("SNMP")
            
            # Extract raw payload if configured
            if self.extract_payload and Raw in packet:
                try:
                    raw_data = packet[Raw].load
                    # Base64 encode binary data for safe storage
                    metadata["payload"] = base64.b64encode(raw_data).decode('utf-8')
                    metadata["payload_length"] = len(raw_data)
                except Exception as e:
                    logger.debug(f"Error extracting payload: {e}")
            
            # Generate Wireshark-like summary
            metadata["summary"] = self._generate_packet_summary(packet, metadata)
            
            # Add detailed protocol tree if deep inspection is enabled
            if self.deep_inspection:
                metadata["protocol_tree"] = self._generate_protocol_tree(packet)
            
            return metadata
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            # Return basic metadata even if processing fails
            return {
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            }
    
    def _extract_ethernet_metadata(self, eth_layer):
        """Extract metadata from Ethernet layer"""
        return {
            "mac_src": eth_layer.src,
            "mac_dst": eth_layer.dst,
            "eth_type": eth_layer.type
        }
    
    def _extract_ipv4_metadata(self, ip_layer):
        """Extract metadata from IPv4 layer"""
        return {
            "ip_version": 4,
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "protocol": ip_layer.proto,
            "ttl": ip_layer.ttl,
            "header_length": ip_layer.ihl * 4,
            "total_length": ip_layer.len,
            "id": ip_layer.id,
            "flags": ip_layer.flags,
            "fragment_offset": ip_layer.frag,
            "tos": ip_layer.tos
        }
    
    def _extract_ipv6_metadata(self, ipv6_layer):
        """Extract metadata from IPv6 layer"""
        return {
            "ip_version": 6,
            "src_ip": ipv6_layer.src,
            "dst_ip": ipv6_layer.dst,
            "next_header": ipv6_layer.nh,
            "hop_limit": ipv6_layer.hlim,
            "traffic_class": ipv6_layer.tc,
            "flow_label": ipv6_layer.fl,
            "payload_length": ipv6_layer.plen
        }
    
    def _extract_tcp_metadata(self, tcp_layer):
        """Extract metadata from TCP layer"""
        flags = {
            'F': 'FIN',
            'S': 'SYN',
            'R': 'RST',
            'P': 'PSH',
            'A': 'ACK',
            'U': 'URG',
            'E': 'ECE',
            'C': 'CWR'
        }
        
        # Extract TCP flags
        tcp_flags = []
        for flag, name in flags.items():
            if tcp_layer.flags & getattr(tcp_layer, flag):
                tcp_flags.append(name)
        
        return {
            "protocol_name": "TCP",
            "src_port": tcp_layer.sport,
            "dst_port": tcp_layer.dport,
            "seq": tcp_layer.seq,
            "ack": tcp_layer.ack,
            "window_size": tcp_layer.window,
            "tcp_flags": tcp_flags,
            "tcp_flags_raw": tcp_layer.flags,
            "payload_size": len(tcp_layer.payload) if hasattr(tcp_layer, 'payload') else 0
        }
    
    def _extract_udp_metadata(self, udp_layer):
        """Extract metadata from UDP layer"""
        return {
            "protocol_name": "UDP",
            "src_port": udp_layer.sport,
            "dst_port": udp_layer.dport,
            "length": udp_layer.len,
            "payload_size": len(udp_layer.payload) if hasattr(udp_layer, 'payload') else 0
        }
    
    def _extract_icmp_metadata(self, icmp_layer):
        """Extract metadata from ICMP layer"""
        return {
            "protocol_name": "ICMP",
            "icmp_type": icmp_layer.type,
            "icmp_code": icmp_layer.code,
            "icmp_id": icmp_layer.id if hasattr(icmp_layer, 'id') else None,
            "icmp_seq": icmp_layer.seq if hasattr(icmp_layer, 'seq') else None
        }
    
    def _extract_icmpv6_metadata(self, icmpv6_layer):
        """Extract metadata from ICMPv6 layer"""
        return {
            "protocol_name": "ICMPv6",
            "icmp_type": icmpv6_layer.type,
            "icmp_code": icmpv6_layer.code
        }
    
    def _extract_arp_metadata(self, arp_layer):
        """Extract metadata from ARP layer"""
        operations = {
            1: "request",
            2: "reply",
            3: "request_reverse",
            4: "reply_reverse",
            5: "drarp_request",
            6: "drarp_reply",
            7: "drarp_error",
            8: "inarp_request",
            9: "inarp_reply"
        }
        
        return {
            "protocol_name": "ARP",
            "arp_op": arp_layer.op,
            "arp_op_name": operations.get(arp_layer.op, "unknown"),
            "arp_hwsrc": arp_layer.hwsrc,
            "arp_hwdst": arp_layer.hwdst,
            "arp_psrc": arp_layer.psrc,
            "arp_pdst": arp_layer.pdst
        }
    
    def _extract_dns_metadata(self, dns_layer):
        """Extract metadata from DNS layer"""
        # Initialize DNS metadata
        dns_metadata = {
            "dns_id": dns_layer.id,
            "dns_qr": dns_layer.qr,  # 0 for query, 1 for response
            "dns_opcode": dns_layer.opcode,
            "dns_query_count": dns_layer.qdcount,
            "dns_answer_count": dns_layer.ancount,
            "dns_query_type": "query" if dns_layer.qr == 0 else "response"
        }
        
        # Extract query information
        if dns_layer.qd and dns_layer.qd.qname:
            dns_metadata["dns_query_name"] = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            dns_metadata["dns_query_type"] = dns_layer.qd.qtype
        
        # Extract response information for DNS responses
        if dns_layer.qr == 1 and dns_layer.an:
            answers = []
            for i in range(dns_layer.ancount):
                if i < len(dns_layer.an):
                    an = dns_layer.an[i]
                    if hasattr(an, 'rdata'):
                        if isinstance(an.rdata, bytes):
                            rdata = socket.inet_ntoa(an.rdata) if an.type == 1 else an.rdata.decode('utf-8', errors='ignore')
                        else:
                            rdata = str(an.rdata)
                        answers.append({
                            "name": an.rrname.decode('utf-8', errors='ignore').rstrip('.') if hasattr(an, 'rrname') else "",
                            "type": an.type,
                            "ttl": an.ttl,
                            "data": rdata
                        })
            
            if answers:
                dns_metadata["dns_answers"] = answers
                dns_metadata["dns_response_code"] = dns_layer.rcode
        
        return {"dns": dns_metadata}
    
    def _extract_http_metadata(self, packet):
        """Extract metadata from HTTP layer"""
        # Check if packet has Raw layer that might contain HTTP data
        if Raw not in packet:
            return None
        
        try:
            # Try to parse HTTP data from Raw layer
            raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Check if this is an HTTP request
            if raw_data.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'TRACE ', 'CONNECT ')):
                # Parse HTTP request
                request_line = raw_data.split('\r\n')[0]
                method, path, version = request_line.split(' ', 2)
                
                # Extract host from headers
                host = None
                for line in raw_data.split('\r\n')[1:]:
                    if line.lower().startswith('host:'):
                        host = line.split(':', 1)[1].strip()
                        break
                
                return {
                    "http": {
                        "type": "request",
                        "method": method,
                        "path": path,
                        "version": version,
                        "host": host,
                        "url": f"http://{host}{path}" if host else path
                    }
                }
            
            # Check if this is an HTTP response
            elif raw_data.startswith(('HTTP/1.0 ', 'HTTP/1.1 ', 'HTTP/2 ')):
                # Parse HTTP response
                status_line = raw_data.split('\r\n')[0]
                version, status_code, reason = status_line.split(' ', 2)
                
                return {
                    "http": {
                        "type": "response",
                        "version": version,
                        "status_code": int(status_code),
                        "reason": reason
                    }
                }
        
        except Exception as e:
            logger.debug(f"Error parsing HTTP data: {e}")
        
        return None
    
    def _determine_direction(self, src_ip):
        """Determine if packet is incoming or outgoing"""
        # This is a simplified approach. In a real implementation,
        # you would check if the source IP belongs to the local network
        # or is one of the machine's IP addresses.
        try:
            # Get local IP addresses
            local_ips = socket.gethostbyname_ex(socket.gethostname())[2]
            
            # Check if source IP is a local IP
            if src_ip in local_ips or src_ip == '127.0.0.1' or src_ip == '::1':
                return "outgoing"
            else:
                return "incoming"
        
        except Exception as e:
            logger.error(f"Error determining packet direction: {e}")
            return "unknown"
    
    def _extract_vlan_metadata(self, vlan_layer):
        """Extract metadata from VLAN layer"""
        return {
            "vlan_id": vlan_layer.vlan,
            "vlan_priority": vlan_layer.prio,
            "vlan_type": vlan_layer.type
        }
    
    def _extract_tls_metadata(self, packet):
        """Extract metadata from TLS layer"""
        if TLS not in packet:
            return None
        
        tls_layer = packet[TLS]
        tls_metadata = {
            "tls": {
                "type": "unknown"
            }
        }
        
        try:
            # Try to determine TLS record type
            if hasattr(tls_layer, 'type'):
                tls_types = {
                    20: "change_cipher_spec",
                    21: "alert",
                    22: "handshake",
                    23: "application_data"
                }
                tls_metadata["tls"]["type"] = tls_types.get(tls_layer.type, f"unknown_{tls_layer.type}")
            
            # Extract TLS version if available
            if hasattr(tls_layer, 'version'):
                tls_versions = {
                    0x0301: "TLSv1.0",
                    0x0302: "TLSv1.1",
                    0x0303: "TLSv1.2",
                    0x0304: "TLSv1.3"
                }
                tls_metadata["tls"]["version"] = tls_versions.get(tls_layer.version, f"unknown_0x{tls_layer.version:04x}")
            
            # Extract handshake type if this is a handshake message
            if tls_metadata["tls"]["type"] == "handshake" and hasattr(tls_layer, 'msg'):
                handshake_types = {
                    1: "client_hello",
                    2: "server_hello",
                    11: "certificate",
                    16: "client_key_exchange",
                    20: "finished"
                }
                if hasattr(tls_layer.msg[0], 'type'):
                    tls_metadata["tls"]["handshake_type"] = handshake_types.get(
                        tls_layer.msg[0].type, f"unknown_{tls_layer.msg[0].type}"
                    )
            
            return tls_metadata
        
        except Exception as e:
            logger.debug(f"Error extracting TLS metadata: {e}")
            return tls_metadata
    
    def _extract_dhcp_metadata(self, packet):
        """Extract metadata from DHCP layer"""
        if BOOTP not in packet:
            return None
        
        bootp_layer = packet[BOOTP]
        dhcp_metadata = {
            "dhcp": {
                "transaction_id": f"0x{bootp_layer.xid:08x}",
                "client_mac": bootp_layer.chaddr[:6].hex(':'),
                "your_ip": bootp_layer.yiaddr,
                "server_ip": bootp_layer.siaddr,
                "gateway_ip": bootp_layer.giaddr
            }
        }
        
        # Extract DHCP options if present
        if DHCP in packet:
            dhcp_layer = packet[DHCP]
            dhcp_metadata["dhcp"]["message_type"] = None
            dhcp_metadata["dhcp"]["options"] = {}
            
            for option in dhcp_layer.options:
                if option == "end" or option == "pad":
                    continue
                
                if isinstance(option, tuple) and len(option) >= 2:
                    option_name, option_value = option[0], option[1]
                    
                    # Handle DHCP message type specially
                    if option_name == "message-type":
                        message_types = {
                            1: "DISCOVER",
                            2: "OFFER",
                            3: "REQUEST",
                            4: "DECLINE",
                            5: "ACK",
                            6: "NAK",
                            7: "RELEASE",
                            8: "INFORM"
                        }
                        dhcp_metadata["dhcp"]["message_type"] = message_types.get(option_value, f"UNKNOWN({option_value})")
                    
                    # Convert bytes to string or hex as appropriate
                    if isinstance(option_value, bytes):
                        try:
                            dhcp_metadata["dhcp"]["options"][option_name] = option_value.decode('utf-8', errors='replace')
                        except:
                            dhcp_metadata["dhcp"]["options"][option_name] = option_value.hex()
                    else:
                        dhcp_metadata["dhcp"]["options"][option_name] = option_value
        
        return dhcp_metadata
    
    def _extract_ntp_metadata(self, packet):
        """Extract metadata from NTP layer"""
        if NTP not in packet:
            return None
        
        ntp_layer = packet[NTP]
        ntp_metadata = {
            "ntp": {
                "version": ntp_layer.version,
                "mode": ntp_layer.mode
            }
        }
        
        # Map NTP mode to human-readable string
        mode_map = {
            0: "reserved",
            1: "symmetric_active",
            2: "symmetric_passive",
            3: "client",
            4: "server",
            5: "broadcast",
            6: "control_message",
            7: "private"
        }
        ntp_metadata["ntp"]["mode_name"] = mode_map.get(ntp_layer.mode, f"unknown_{ntp_layer.mode}")
        
        # Extract timestamps if available
        if hasattr(ntp_layer, 'ref'):
            ntp_metadata["ntp"]["reference_timestamp"] = ntp_layer.ref
        if hasattr(ntp_layer, 'orig'):
            ntp_metadata["ntp"]["originate_timestamp"] = ntp_layer.orig
        if hasattr(ntp_layer, 'recv'):
            ntp_metadata["ntp"]["receive_timestamp"] = ntp_layer.recv
        if hasattr(ntp_layer, 'sent'):
            ntp_metadata["ntp"]["transmit_timestamp"] = ntp_layer.sent
        
        return ntp_metadata
    
    def _extract_smtp_metadata(self, packet):
        """Extract metadata from SMTP layer"""
        if TCP not in packet or Raw not in packet:
            return None
        
        try:
            # Try to parse SMTP data from Raw layer
            raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Check for SMTP commands or responses
            smtp_metadata = {"smtp": {}}
            
            # Check for SMTP response (starts with 3-digit code)
            if raw_data[:3].isdigit() and len(raw_data) > 4 and raw_data[3] in [' ', '-']:
                code = int(raw_data[:3])
                smtp_metadata["smtp"]["type"] = "response"
                smtp_metadata["smtp"]["code"] = code
                smtp_metadata["smtp"]["message"] = raw_data[4:].strip()
                
                # Categorize response code
                if 200 <= code < 300:
                    smtp_metadata["smtp"]["status"] = "positive_completion"
                elif 300 <= code < 400:
                    smtp_metadata["smtp"]["status"] = "positive_intermediate"
                elif 400 <= code < 500:
                    smtp_metadata["smtp"]["status"] = "transient_negative"
                elif 500 <= code < 600:
                    smtp_metadata["smtp"]["status"] = "permanent_negative"
                else:
                    smtp_metadata["smtp"]["status"] = "unknown"
            
            # Check for SMTP commands
            else:
                command_line = raw_data.split('\r\n')[0].strip()
                if ' ' in command_line:
                    command, args = command_line.split(' ', 1)
                else:
                    command, args = command_line, ""
                
                command = command.upper()
                smtp_commands = ["HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "VRFY", 
                                "EXPN", "HELP", "NOOP", "QUIT", "AUTH", "STARTTLS"]
                
                if command in smtp_commands:
                    smtp_metadata["smtp"]["type"] = "command"
                    smtp_metadata["smtp"]["command"] = command
                    smtp_metadata["smtp"]["arguments"] = args
                else:
                    # Not a recognized SMTP command or response
                    return None
            
            return smtp_metadata
        
        except Exception as e:
            logger.debug(f"Error extracting SMTP metadata: {e}")
            return None
    
    def _extract_ftp_metadata(self, packet):
        """Extract metadata from FTP layer"""
        if TCP not in packet or Raw not in packet:
            return None
        
        try:
            # Try to parse FTP data from Raw layer
            raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Check for FTP commands or responses
            ftp_metadata = {"ftp": {}}
            
            # Check for FTP response (starts with 3-digit code)
            if raw_data[:3].isdigit() and len(raw_data) > 4 and raw_data[3] in [' ', '-']:
                code = int(raw_data[:3])
                ftp_metadata["ftp"]["type"] = "response"
                ftp_metadata["ftp"]["code"] = code
                ftp_metadata["ftp"]["message"] = raw_data[4:].strip()
                
                # Categorize response code
                if 100 <= code < 200:
                    ftp_metadata["ftp"]["status"] = "positive_preliminary"
                elif 200 <= code < 300:
                    ftp_metadata["ftp"]["status"] = "positive_completion"
                elif 300 <= code < 400:
                    ftp_metadata["ftp"]["status"] = "positive_intermediate"
                elif 400 <= code < 500:
                    ftp_metadata["ftp"]["status"] = "transient_negative"
                elif 500 <= code < 600:
                    ftp_metadata["ftp"]["status"] = "permanent_negative"
                else:
                    ftp_metadata["ftp"]["status"] = "unknown"
            
            # Check for FTP commands
            else:
                command_line = raw_data.split('\r\n')[0].strip()
                if ' ' in command_line:
                    command, args = command_line.split(' ', 1)
                else:
                    command, args = command_line, ""
                
                command = command.upper()
                ftp_commands = ["USER", "PASS", "ACCT", "CWD", "CDUP", "SMNT", "QUIT", "REIN", 
                               "PORT", "PASV", "TYPE", "STRU", "MODE", "RETR", "STOR", "STOU", 
                               "APPE", "ALLO", "REST", "RNFR", "RNTO", "ABOR", "DELE", "RMD", 
                               "MKD", "PWD", "LIST", "NLST", "SITE", "SYST", "STAT", "HELP", "NOOP"]
                
                if command in ftp_commands:
                    ftp_metadata["ftp"]["type"] = "command"
                    ftp_metadata["ftp"]["command"] = command
                    ftp_metadata["ftp"]["arguments"] = args
                else:
                    # Not a recognized FTP command or response
                    return None
            
            return ftp_metadata
        
        except Exception as e:
            logger.debug(f"Error extracting FTP metadata: {e}")
            return None
    
    def _extract_snmp_metadata(self, packet):
        """Extract metadata from SNMP layer"""
        if SNMP not in packet:
            return None
        
        snmp_layer = packet[SNMP]
        snmp_metadata = {
            "snmp": {
                "version": snmp_layer.version
            }
        }
        
        # Map SNMP version to human-readable string
        version_map = {
            0: "v1",
            1: "v2c",
            3: "v3"
        }
        snmp_metadata["snmp"]["version_name"] = version_map.get(snmp_layer.version, f"unknown_{snmp_layer.version}")
        
        # Extract community string for v1/v2c
        if snmp_layer.version in [0, 1] and hasattr(snmp_layer, 'community'):
            try:
                snmp_metadata["snmp"]["community"] = snmp_layer.community.decode('utf-8', errors='replace')
            except:
                snmp_metadata["snmp"]["community"] = snmp_layer.community.hex()
        
        # Extract PDU type
        if hasattr(snmp_layer, 'PDU'):
            pdu_types = {
                0: "get-request",
                1: "get-next-request",
                2: "response",
                3: "set-request",
                4: "trap-v1",
                5: "get-bulk-request",
                6: "inform-request",
                7: "trap-v2",
                8: "report"
            }
            pdu_type = getattr(snmp_layer.PDU, 'pdutypes', None)
            if pdu_type is not None:
                snmp_metadata["snmp"]["pdu_type"] = pdu_types.get(pdu_type, f"unknown_{pdu_type}")
        
        return snmp_metadata
    
    def _generate_packet_summary(self, packet, metadata):
        """Generate a Wireshark-like packet summary"""
        summary = ""
        
        # Start with protocol
        if "protocol_name" in metadata:
            protocol = metadata["protocol_name"]
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
            if "window_size" in metadata:
                summary += f" Win={metadata['window_size']}"
        
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
                
                # Add code information for certain types
                if icmp_type == 3:  # Destination Unreachable
                    unreachable_codes = {
                        0: "Network Unreachable",
                        1: "Host Unreachable",
                        2: "Protocol Unreachable",
                        3: "Port Unreachable",
                        4: "Fragmentation Needed",
                        5: "Source Route Failed"
                    }
                    code = metadata["icmp_code"]
                    summary += f" ({unreachable_codes.get(code, f'Code {code}')})"
        
        elif protocol == "ARP":
            if "arp_op_name" in metadata:
                summary += f" {metadata['arp_op_name']}"
                
                if "arp_psrc" in metadata and "arp_pdst" in metadata:
                    if metadata["arp_op_name"] == "request":
                        summary += f" who-has {metadata['arp_pdst']} tell {metadata['arp_psrc']}"
                    elif metadata["arp_op_name"] == "reply":
                        summary += f" {metadata['arp_psrc']} is-at {metadata['arp_hwsrc']}"
        
        elif protocol == "DNS":
            if "dns" in metadata:
                dns_info = metadata["dns"]
                if dns_info.get("dns_query_type") == "query":
                    summary += " Standard query"
                    if "dns_query_name" in dns_info:
                        summary += f" {dns_info['dns_query_name']}"
                elif dns_info.get("dns_query_type") == "response":
                    summary += " Standard response"
                    if "dns_response_code" in dns_info:
                        response_codes = {
                            0: "No error",
                            1: "Format error",
                            2: "Server failure",
                            3: "Name error",
                            4: "Not implemented",
                            5: "Refused"
                        }
                        code = dns_info["dns_response_code"]
                        summary += f" {response_codes.get(code, f'Code {code}')}"
        
        elif protocol == "HTTP":
            if "http" in metadata:
                http_info = metadata["http"]
                if http_info.get("type") == "request":
                    summary += f" {http_info.get('method', 'Unknown')} {http_info.get('path', '/')}"
                    if "host" in http_info:
                        summary += f" Host: {http_info['host']}"
                elif http_info.get("type") == "response":
                    status = http_info.get("status_code", 0)
                    reason = http_info.get("reason", "Unknown")
                    summary += f" {status} {reason}"
        
        elif protocol == "TLS":
            if "tls" in metadata:
                tls_info = metadata["tls"]
                if "type" in tls_info:
                    if tls_info["type"] == "handshake" and "handshake_type" in tls_info:
                        summary += f" {tls_info['handshake_type'].replace('_', ' ').title()}"
                    else:
                        summary += f" {tls_info['type'].replace('_', ' ').title()}"
                if "version" in tls_info:
                    summary += f" {tls_info['version']}"
        
        elif protocol == "DHCP":
            if "dhcp" in metadata and "message_type" in metadata["dhcp"]:
                summary += f" {metadata['dhcp']['message_type']}"
                
                # Add client and assigned IP information
                if "client_mac" in metadata["dhcp"]:
                    summary += f" Client MAC: {metadata['dhcp']['client_mac']}"
                if metadata["dhcp"]["message_type"] in ["OFFER", "ACK"] and "your_ip" in metadata["dhcp"]:
                    summary += f" Your IP: {metadata['dhcp']['your_ip']}"
        
        # Add length information if not already added
        if "packet_length" in metadata and not "Len=" in summary:
            summary += f" Length: {metadata['packet_length']} bytes"
        
        # Prepend protocol to summary
        summary = f"{protocol}: {summary}"
        
        return summary
    
    def _generate_protocol_tree(self, packet):
        """Generate a detailed protocol tree for deep inspection"""
        tree = []
        
        # Helper function to safely convert packet field values to JSON-serializable format
        def safe_value(val):
            if isinstance(val, (int, float, bool, str, type(None))):
                return val
            elif isinstance(val, bytes):
                try:
                    return val.decode('utf-8', errors='replace')
                except:
                    return f"0x{val.hex()}"
            elif isinstance(val, list):
                return [safe_value(v) for v in val]
            elif isinstance(val, dict):
                return {k: safe_value(v) for k, v in val.items()}
            else:
                return str(val)
        
        # Process each layer in the packet
        current_layer = packet
        while current_layer:
            layer_name = current_layer.name
            layer_fields = {}
            
            # Extract all fields from the current layer
            if hasattr(current_layer, 'fields'):
                for field_name, field_value in current_layer.fields.items():
                    layer_fields[field_name] = safe_value(field_value)
            
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