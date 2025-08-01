"""
Capture Manager module for coordinating packet capture and processing
with support for multi-interface capture and advanced features
"""

import os
import time
import logging
import threading
import queue
import asyncio
from datetime import datetime
from pathlib import Path

from pyguard.core.packet_capture import PacketCapture
from pyguard.core.packet_processor import PacketProcessor
from pyguard.storage.database_storage import DatabaseStorage
from pyguard.storage.csv_storage import CSVStorage
from pyguard.storage.json_storage import JSONStorage

logger = logging.getLogger(__name__)

class CaptureManager:
    """Manages packet capture and processing workflow with multi-interface support"""
    
    def __init__(self, config):
        """Initialize capture manager with configuration"""
        self.config = config
        self.output_dir = Path(config.output_dir)
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Check for multi-interface configuration
        self.multi_interface = len(config.interfaces) > 0
        
        if self.multi_interface:
            # Create packet capture instances for each interface
            self.packet_captures = {}
            for interface in config.interfaces:
                # Create a copy of the config with the specific interface
                interface_config = self._create_interface_config(config, interface)
                self.packet_captures[interface] = PacketCapture(interface_config)
        else:
            # Create a single packet capture instance
            self.packet_captures = {config.interface: PacketCapture(config)}
        
        # Create packet processor instance
        self.packet_processor = PacketProcessor(config)
        
        # Create storage instances
        self.db_storage = None
        if config.database["enabled"]:
            self.db_storage = DatabaseStorage(config)
        
        self.csv_storage = None
        if config.csv_export["enabled"]:
            self.csv_storage = CSVStorage(config)
        
        self.json_storage = None
        if config.json_export["enabled"]:
            self.json_storage = JSONStorage(config)
        
        # Processing threads
        self.processing_threads = []
        self.num_processing_threads = config.capture["processing_threads"]
        
        # Async mode
        self.async_mode = config.capture.get("async_mode", False)
        self.async_loop = None
        self.async_tasks = []
        
        # Packet filter (for live filtering)
        self.packet_filter = None
        
        # Statistics
        self.stats = {
            "packets_processed": 0,
            "packets_stored_db": 0,
            "packets_stored_csv": 0,
            "packets_stored_json": 0,
            "packets_filtered": 0,
            "processing_errors": 0,
            "start_time": None,
            "last_update_time": None,
            "interfaces": {}
        }
        
        # Initialize per-interface statistics
        for interface in self.packet_captures.keys():
            self.stats["interfaces"][interface] = {
                "packets_captured": 0,
                "packets_dropped": 0
            }
        
        # Control flags
        self.running = False
        
        # Packet buffer for live viewing
        self.live_packet_buffer = queue.Queue(maxsize=10000)  # Buffer for live packet viewing
        self.live_packet_lock = threading.Lock()
    
    def _create_interface_config(self, base_config, interface):
        """Create a config copy with a specific interface"""
        # This is a simplified approach - in a real implementation,
        # you would create a proper deep copy of the config object
        import copy
        interface_config = copy.deepcopy(base_config)
        interface_config.interface = interface
        return interface_config
    
    def start(self):
        """Start capture and processing"""
        if self.running:
            logger.warning("Capture manager already running")
            return False
        
        try:
            logger.info("Starting capture manager")
            
            # Initialize storage
            if self.db_storage:
                self.db_storage.connect()
                self.db_storage.initialize_schema()
            
            if self.csv_storage:
                self.csv_storage.initialize()
            
            # Start packet capture
            if not self.packet_capture.start():
                logger.error("Failed to start packet capture")
                return False
            
            # Start processing threads
            self.running = True
            self.stats["start_time"] = time.time()
            self.stats["last_update_time"] = time.time()
            
            for i in range(self.num_processing_threads):
                thread = threading.Thread(
                    target=self._processing_thread,
                    name=f"ProcessingThread-{i}",
                    daemon=True
                )
                thread.start()
                self.processing_threads.append(thread)
            
            logger.info(f"Started {self.num_processing_threads} processing threads")
            
            # Start statistics thread
            self.stats_thread = threading.Thread(
                target=self._stats_thread,
                name="StatsThread",
                daemon=True
            )
            self.stats_thread.start()
            
            return True
        
        except Exception as e:
            logger.error(f"Error starting capture manager: {e}")
            self.running = False
            return False
    
    def stop(self):
        """Stop capture and processing"""
        if not self.running:
            logger.warning("Capture manager not running")
            return
        
        logger.info("Stopping capture manager")
        self.running = False
        
        # Stop packet capture
        self.packet_capture.stop()
        
        # Wait for processing threads to finish
        for thread in self.processing_threads:
            thread.join(timeout=5)
        
        # Close storage connections
        if self.db_storage:
            self.db_storage.commit()
            self.db_storage.close()
        
        if self.csv_storage:
            self.csv_storage.close()
        
        # Log final statistics
        self._log_statistics()
        
        logger.info("Capture manager stopped")
    
    def _processing_thread(self):
        """Processing thread function"""
        logger.info(f"Processing thread {threading.current_thread().name} started")
        
        batch_size = self.config.capture["batch_size"]
        batch_items = []
        last_commit_time = time.time()
        commit_interval = self.config.database["commit_interval"]
        
        while self.running or not self.packet_capture.packet_queue.empty():
            try:
                # Get packet from queue with timeout
                packet_data = self.packet_capture.get_packet(timeout=0.1)
                if not packet_data:
                    # Check if it's time to commit the current batch
                    if batch_items and (time.time() - last_commit_time) > commit_interval:
                        self._store_batch(batch_items)
                        batch_items = []
                        last_commit_time = time.time()
                    continue
                
                header, packet = packet_data
                
                # Process packet to extract metadata
                metadata = self.packet_processor.process_packet(header, packet)
                
                # Add to batch
                batch_items.append(metadata)
                
                # Mark packet as processed
                self.packet_capture.task_done()
                
                # Update statistics
                self.stats["packets_processed"] += 1
                
                # Store batch if it reaches the batch size
                if len(batch_items) >= batch_size:
                    self._store_batch(batch_items)
                    batch_items = []
                    last_commit_time = time.time()
            
            except Exception as e:
                logger.error(f"Error in processing thread: {e}")
                self.stats["processing_errors"] += 1
                time.sleep(0.1)  # Avoid tight error loop
        
        # Store any remaining items in the batch
        if batch_items:
            self._store_batch(batch_items)
        
        logger.info(f"Processing thread {threading.current_thread().name} stopped")
    
    def _store_batch(self, batch_items):
        """Store a batch of processed packets"""
        if not batch_items:
            return
        
        # Store in database if enabled
        if self.db_storage:
            try:
                self.db_storage.store_batch(batch_items)
                self.stats["packets_stored_db"] += len(batch_items)
            except Exception as e:
                logger.error(f"Error storing batch in database: {e}")
        
        # Store in CSV if enabled
        if self.csv_storage:
            try:
                self.csv_storage.store_batch(batch_items)
                self.stats["packets_stored_csv"] += len(batch_items)
            except Exception as e:
                logger.error(f"Error storing batch in CSV: {e}")
    
    def _stats_thread(self):
        """Statistics thread function"""
        logger.info("Statistics thread started")
        
        while self.running:
            try:
                # Sleep for a while
                time.sleep(10)
                
                # Log statistics
                self._log_statistics()
            
            except Exception as e:
                logger.error(f"Error in statistics thread: {e}")
                time.sleep(1)  # Avoid tight error loop
        
        logger.info("Statistics thread stopped")
    
    def _log_statistics(self):
        """Log capture and processing statistics"""
        current_time = time.time()
        elapsed = current_time - self.stats["start_time"]
        interval = current_time - self.stats["last_update_time"]
        self.stats["last_update_time"] = current_time
        
        # Get capture statistics
        capture_stats = self.packet_capture.get_stats()
        
        # Calculate rates
        packets_per_second = self.stats["packets_processed"] / elapsed if elapsed > 0 else 0
        interval_packets = self.stats["packets_processed"] - self.stats.get("last_packets_processed", 0)
        interval_rate = interval_packets / interval if interval > 0 else 0
        self.stats["last_packets_processed"] = self.stats["packets_processed"]
        
        # Log statistics
        logger.info(
            f"Statistics: Processed={self.stats['packets_processed']} "
            f"(avg={packets_per_second:.1f}/s, current={interval_rate:.1f}/s), "
            f"DB={self.stats['packets_stored_db']}, CSV={self.stats['packets_stored_csv']}, "
            f"Errors={self.stats['processing_errors']}, "
            f"Queue={capture_stats.get('queue_size', 'N/A')}, "
            f"Dropped={capture_stats.get('dropped', 'N/A')}"
        )
    
    def get_statistics(self):
        """Get current statistics"""
        stats = self.stats.copy()
        
        # Add capture statistics
        capture_stats = self.packet_capture.get_stats()
        stats.update(capture_stats)
        
        # Calculate elapsed time and rates
        current_time = time.time()
        if stats["start_time"]:
            elapsed = current_time - stats["start_time"]
            stats["elapsed_time"] = elapsed
            stats["packets_per_second"] = stats["packets_processed"] / elapsed if elapsed > 0 else 0
        
        return stats