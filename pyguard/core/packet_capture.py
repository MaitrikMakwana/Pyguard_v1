"""
Packet capture module using scapy and pcapy
"""

import os
import time
import logging
import threading
import queue
from datetime import datetime
from pathlib import Path

import pcapy
from scapy.all import Ether, wrpcap, PcapWriter

from pyguard.utils.system_monitor import SystemMonitor

logger = logging.getLogger(__name__)

class PacketCapture:
    """High-performance packet capture class"""
    
    def __init__(self, config):
        """Initialize packet capture with configuration"""
        self.config = config
        self.interface = config.interface
        self.output_dir = Path(config.output_dir)
        self.bpf_filter = config.capture["bpf_filter"]
        self.snaplen = config.capture["snaplen"]
        self.promiscuous = config.capture["promiscuous"]
        self.buffer_size = config.capture["buffer_size_mb"] * 1024 * 1024  # Convert MB to bytes
        
        # Create packet queue for processing
        self.packet_queue = queue.Queue(maxsize=100000)  # Limit queue size to prevent memory issues
        
        # Setup system monitor
        self.system_monitor = SystemMonitor(
            memory_limit=config.system["memory_limit_percent"],
            cpu_limit=config.system["cpu_limit_percent"],
            check_interval=config.system["check_interval_seconds"]
        )
        
        # Setup PCAP writer
        self.pcap_enabled = config.pcap["enabled"]
        if self.pcap_enabled:
            self.pcap_dir = self.output_dir / "pcap"
            os.makedirs(self.pcap_dir, exist_ok=True)
            self.current_pcap_file = None
            self.pcap_writer = None
            self.pcap_start_time = None
            self.pcap_packet_count = 0
            self.rotate_size = config.pcap["rotate_size_mb"] * 1024 * 1024  # Convert MB to bytes
            self.rotate_interval = config.pcap["rotate_interval_minutes"] * 60  # Convert minutes to seconds
        
        # Capture control
        self.running = False
        self.capture_thread = None
        self.pcap_writer_thread = None
        self.pcap_writer_queue = queue.Queue(maxsize=10000)
    
    def start(self):
        """Start packet capture"""
        if self.running:
            logger.warning("Packet capture already running")
            return False
        
        try:
            # Start system monitor
            self.system_monitor.start()
            
            # Open capture device
            self.pcap = pcapy.open_live(
                self.interface,
                self.snaplen,
                self.promiscuous,
                100  # Timeout in ms
            )
            
            # Set BPF filter if specified
            if self.bpf_filter:
                self.pcap.setfilter(self.bpf_filter)
            
            # Set non-blocking mode
            self.pcap.setnonblock(1)
            
            # Start capture thread
            self.running = True
            self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
            self.capture_thread.start()
            
            # Start PCAP writer thread if enabled
            if self.pcap_enabled:
                self._rotate_pcap_file()  # Create initial PCAP file
                self.pcap_writer_thread = threading.Thread(target=self._pcap_writer_loop, daemon=True)
                self.pcap_writer_thread.start()
            
            logger.info(f"Started packet capture on interface {self.interface}")
            return True
        
        except Exception as e:
            logger.error(f"Error starting packet capture: {e}")
            self.running = False
            return False
    
    def stop(self):
        """Stop packet capture"""
        if not self.running:
            logger.warning("Packet capture not running")
            return
        
        logger.info("Stopping packet capture...")
        self.running = False
        
        # Wait for capture thread to finish
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
        
        # Wait for PCAP writer thread to finish
        if self.pcap_writer_thread and self.pcap_writer_thread.is_alive():
            self.pcap_writer_thread.join(timeout=5)
        
        # Close PCAP writer
        if self.pcap_writer:
            self.pcap_writer.close()
            self.pcap_writer = None
        
        # Stop system monitor
        self.system_monitor.stop()
        
        logger.info("Packet capture stopped")
    
    def _capture_loop(self):
        """Main capture loop running in a separate thread"""
        logger.info("Capture loop started")
        
        while self.running:
            try:
                # Check system resources
                if self.system_monitor.is_overloaded():
                    logger.warning("System resources overloaded, slowing down capture")
                    time.sleep(1)
                    continue
                
                # Capture packets in a batch to improve performance
                for _ in range(self.config.capture["batch_size"]):
                    if not self.running:
                        break
                    
                    # Capture a single packet
                    header, packet = self.pcap.next()
                    if header is None:
                        # No packet available, sleep briefly to avoid CPU spinning
                        time.sleep(0.001)
                        break
                    
                    # Convert to scapy packet for easier processing
                    try:
                        scapy_packet = Ether(packet)
                        
                        # Add packet to processing queue
                        try:
                            self.packet_queue.put((header, scapy_packet), block=False)
                        except queue.Full:
                            logger.warning("Packet queue full, dropping packet")
                        
                        # Add to PCAP writer queue if enabled
                        if self.pcap_enabled:
                            try:
                                self.pcap_writer_queue.put((header, packet), block=False)
                            except queue.Full:
                                logger.warning("PCAP writer queue full, dropping packet")
                    
                    except Exception as e:
                        logger.error(f"Error processing packet: {e}")
            
            except Exception as e:
                logger.error(f"Error in capture loop: {e}")
                if self.running:
                    # Sleep briefly to avoid tight error loop
                    time.sleep(1)
        
        logger.info("Capture loop stopped")
    
    def _pcap_writer_loop(self):
        """PCAP writer loop running in a separate thread"""
        logger.info("PCAP writer loop started")
        
        last_rotation_check = time.time()
        
        while self.running or not self.pcap_writer_queue.empty():
            try:
                # Check if we need to rotate PCAP file
                current_time = time.time()
                if (current_time - last_rotation_check) > 10:  # Check every 10 seconds
                    self._check_pcap_rotation()
                    last_rotation_check = current_time
                
                # Get packet from queue with timeout
                try:
                    header, packet = self.pcap_writer_queue.get(timeout=0.1)
                except queue.Empty:
                    continue
                
                # Write packet to PCAP file
                if self.pcap_writer:
                    self.pcap_writer.write(packet)
                    self.pcap_packet_count += 1
                
                # Mark task as done
                self.pcap_writer_queue.task_done()
            
            except Exception as e:
                logger.error(f"Error in PCAP writer loop: {e}")
                time.sleep(1)
        
        logger.info("PCAP writer loop stopped")
    
    def _check_pcap_rotation(self):
        """Check if PCAP file needs to be rotated"""
        if not self.pcap_writer:
            return
        
        current_time = time.time()
        rotate_by_time = (current_time - self.pcap_start_time) > self.rotate_interval
        rotate_by_size = os.path.getsize(self.current_pcap_file) > self.rotate_size
        
        if rotate_by_time or rotate_by_size:
            logger.info(f"Rotating PCAP file: time={rotate_by_time}, size={rotate_by_size}")
            self._rotate_pcap_file()
    
    def _rotate_pcap_file(self):
        """Rotate PCAP file"""
        # Close current PCAP writer if exists
        if self.pcap_writer:
            self.pcap_writer.close()
            logger.info(f"Closed PCAP file {self.current_pcap_file} with {self.pcap_packet_count} packets")
        
        # Create new PCAP file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"capture_{self.interface}_{timestamp}.pcap"
        self.current_pcap_file = self.pcap_dir / filename
        self.pcap_writer = PcapWriter(str(self.current_pcap_file), append=False, sync=True)
        self.pcap_start_time = time.time()
        self.pcap_packet_count = 0
        
        logger.info(f"Created new PCAP file: {self.current_pcap_file}")
        
        # Clean up old PCAP files if needed
        self._cleanup_old_pcap_files()
    
    def _cleanup_old_pcap_files(self):
        """Clean up old PCAP files based on max_files setting"""
        max_files = self.config.pcap["max_files"]
        if max_files <= 0:
            return
        
        # Get list of PCAP files sorted by modification time (oldest first)
        pcap_files = sorted(
            self.pcap_dir.glob("*.pcap"),
            key=lambda x: x.stat().st_mtime
        )
        
        # Remove oldest files if we have too many
        while len(pcap_files) > max_files:
            oldest_file = pcap_files.pop(0)
            try:
                oldest_file.unlink()
                logger.info(f"Deleted old PCAP file: {oldest_file}")
            except Exception as e:
                logger.error(f"Error deleting old PCAP file {oldest_file}: {e}")
    
    def get_packet(self, block=True, timeout=None):
        """Get a packet from the processing queue"""
        try:
            return self.packet_queue.get(block=block, timeout=timeout)
        except queue.Empty:
            return None
    
    def task_done(self):
        """Mark a packet as processed"""
        self.packet_queue.task_done()
    
    def get_stats(self):
        """Get capture statistics"""
        try:
            stats = self.pcap.stats()
            return {
                "received": stats[0],
                "dropped": stats[1],
                "ifdropped": stats[2] if len(stats) > 2 else 0,
                "queue_size": self.packet_queue.qsize(),
                "pcap_queue_size": self.pcap_writer_queue.qsize() if self.pcap_enabled else 0,
                "pcap_packet_count": self.pcap_packet_count if self.pcap_enabled else 0,
                "system_load": self.system_monitor.get_current_load()
            }
        except Exception as e:
            logger.error(f"Error getting capture statistics: {e}")
            return {
                "error": str(e)
            }