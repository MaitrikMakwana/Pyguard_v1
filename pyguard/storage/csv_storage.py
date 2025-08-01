"""
CSV storage module for packet metadata
"""

import os
import csv
import json
import logging
import time
from datetime import datetime
from pathlib import Path
import threading
import pandas as pd

logger = logging.getLogger(__name__)

class CSVStorage:
    """Store packet metadata in CSV files"""
    
    def __init__(self, config):
        """Initialize CSV storage with configuration"""
        self.config = config
        self.csv_config = config.csv_export
        self.directory = Path(self.csv_config["directory"])
        self.rotate_interval = self.csv_config["rotate_interval_minutes"] * 60  # Convert to seconds
        self.max_files = self.csv_config["max_files"]
        
        # Create output directory
        os.makedirs(self.directory, exist_ok=True)
        
        # CSV file handling
        self.current_file = None
        self.writer = None
        self.csv_file = None
        self.start_time = None
        self.lock = threading.Lock()
        
        # Define CSV fields
        self.csv_fields = [
            'timestamp', 'timestamp_epoch', 'capture_length', 'packet_length',
            'mac_src', 'mac_dst', 'eth_type', 'ip_version', 'src_ip', 'dst_ip',
            'protocol', 'protocol_name', 'src_port', 'dst_port', 'direction',
            'ttl', 'header_length', 'total_length', 'flags', 'fragment_offset',
            'window_size', 'tcp_flags_raw', 'payload_size', 'icmp_type', 'icmp_code',
            'arp_op', 'arp_op_name', 'dns', 'http'
        ]
    
    def initialize(self):
        """Initialize CSV storage"""
        try:
            logger.info(f"Initializing CSV storage in {self.directory}")
            self._rotate_file()
            return True
        except Exception as e:
            logger.error(f"Error initializing CSV storage: {e}")
            return False
    
    def store_batch(self, batch_items):
        """Store a batch of packet metadata in CSV file"""
        if not self.writer:
            logger.error("CSV writer not initialized")
            return False
        
        try:
            with self.lock:
                # Check if we need to rotate the file
                if self._should_rotate():
                    self._rotate_file()
                
                # Prepare rows for CSV
                rows = []
                for metadata in batch_items:
                    row = {}
                    
                    # Extract basic fields
                    for field in self.csv_fields:
                        if field in metadata:
                            # Handle special JSON fields
                            if field in ['dns', 'http', 'tcp_flags'] and metadata[field]:
                                row[field] = json.dumps(metadata[field])
                            else:
                                row[field] = metadata[field]
                        else:
                            row[field] = None
                    
                    rows.append(row)
                
                # Write rows to CSV
                self.writer.writerows(rows)
                self.csv_file.flush()  # Ensure data is written to disk
            
            return True
        
        except Exception as e:
            logger.error(f"Error storing batch in CSV: {e}")
            return False
    
    def _should_rotate(self):
        """Check if CSV file should be rotated"""
        if not self.start_time:
            return True
        
        current_time = time.time()
        return (current_time - self.start_time) > self.rotate_interval
    
    def _rotate_file(self):
        """Rotate CSV file"""
        # Close current file if open
        if self.csv_file:
            self.csv_file.close()
            logger.info(f"Closed CSV file: {self.current_file}")
            
            # Convert to Parquet for better storage efficiency
            self._convert_to_parquet(self.current_file)
        
        # Create new CSV file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"packets_{timestamp}.csv"
        self.current_file = self.directory / filename
        
        # Open file and create CSV writer
        self.csv_file = open(self.current_file, 'w', newline='')
        self.writer = csv.DictWriter(self.csv_file, fieldnames=self.csv_fields)
        self.writer.writeheader()
        
        # Update start time
        self.start_time = time.time()
        
        logger.info(f"Created new CSV file: {self.current_file}")
        
        # Clean up old files if needed
        self._cleanup_old_files()
    
    def _convert_to_parquet(self, csv_file):
        """Convert CSV file to Parquet format for better storage efficiency"""
        try:
            parquet_file = csv_file.with_suffix('.parquet')
            
            # Read CSV file
            df = pd.read_csv(csv_file)
            
            # Convert JSON string columns to actual JSON
            for col in ['dns', 'http', 'tcp_flags']:
                if col in df.columns:
                    df[col] = df[col].apply(lambda x: json.loads(x) if isinstance(x, str) and x else None)
            
            # Write to Parquet
            df.to_parquet(parquet_file, index=False, compression='snappy')
            
            logger.info(f"Converted {csv_file} to Parquet format: {parquet_file}")
            
            # Optionally remove the original CSV file to save space
            # os.remove(csv_file)
        
        except Exception as e:
            logger.error(f"Error converting CSV to Parquet: {e}")
    
    def _cleanup_old_files(self):
        """Clean up old CSV and Parquet files based on max_files setting"""
        if self.max_files <= 0:
            return
        
        try:
            # Get list of CSV files sorted by modification time (oldest first)
            csv_files = sorted(
                self.directory.glob("*.csv"),
                key=lambda x: x.stat().st_mtime
            )
            
            # Get list of Parquet files sorted by modification time (oldest first)
            parquet_files = sorted(
                self.directory.glob("*.parquet"),
                key=lambda x: x.stat().st_mtime
            )
            
            # Count total files (excluding current file)
            total_files = len(csv_files) + len(parquet_files)
            if self.current_file in csv_files:
                total_files -= 1
            
            # Remove oldest files if we have too many
            files_to_remove = total_files - self.max_files
            if files_to_remove <= 0:
                return
            
            # Remove oldest files
            for _ in range(files_to_remove):
                if parquet_files:
                    oldest_file = parquet_files.pop(0)
                elif csv_files:
                    oldest_file = csv_files.pop(0)
                else:
                    break
                
                if oldest_file != self.current_file:
                    try:
                        oldest_file.unlink()
                        logger.info(f"Deleted old file: {oldest_file}")
                    except Exception as e:
                        logger.error(f"Error deleting old file {oldest_file}: {e}")
        
        except Exception as e:
            logger.error(f"Error cleaning up old files: {e}")
    
    def close(self):
        """Close CSV storage"""
        try:
            with self.lock:
                if self.csv_file:
                    self.csv_file.close()
                    self.csv_file = None
                    self.writer = None
                    
                    # Convert last file to Parquet
                    if self.current_file:
                        self._convert_to_parquet(self.current_file)
                        self.current_file = None
            
            logger.info("CSV storage closed")
            return True
        
        except Exception as e:
            logger.error(f"Error closing CSV storage: {e}")
            return False