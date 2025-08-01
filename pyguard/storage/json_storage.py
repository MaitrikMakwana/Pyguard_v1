"""
JSON storage module for exporting packet metadata to JSON files
"""

import os
import json
import time
import logging
from datetime import datetime
from pathlib import Path
import threading

logger = logging.getLogger(__name__)

class JSONStorage:
    """Store packet metadata in JSON files with rotation support"""
    
    def __init__(self, config):
        """Initialize JSON storage with configuration"""
        self.config = config
        self.json_dir = Path(config.json_export["directory"])
        self.rotate_interval = config.json_export["rotate_interval_minutes"] * 60  # Convert to seconds
        self.max_files = config.json_export["max_files"]
        self.pretty_print = config.json_export.get("pretty_print", True)
        
        # Create JSON directory if it doesn't exist
        os.makedirs(self.json_dir, exist_ok=True)
        
        # Initialize file handle
        self.current_file = None
        self.file_start_time = None
        self.lock = threading.Lock()
    
    def initialize(self):
        """Initialize JSON storage"""
        self._rotate_file()
    
    def store_batch(self, batch_items):
        """Store a batch of packet metadata to JSON file"""
        if not batch_items:
            return
        
        with self.lock:
            # Check if we need to rotate the file
            if self._should_rotate():
                self._rotate_file()
            
            # Write batch to file
            try:
                with open(self.current_file, 'a') as f:
                    for item in batch_items:
                        if self.pretty_print:
                            json.dump(item, f, indent=2)
                        else:
                            json.dump(item, f)
                        f.write('\n')  # Add newline between JSON objects
            except Exception as e:
                logger.error(f"Error writing to JSON file: {e}")
    
    def close(self):
        """Close JSON storage"""
        # Nothing to do here, files are opened and closed for each batch
        pass
    
    def _should_rotate(self):
        """Check if the current file should be rotated"""
        if not self.current_file or not self.file_start_time:
            return True
        
        # Check if file exists
        if not os.path.exists(self.current_file):
            return True
        
        # Check if rotation interval has passed
        current_time = time.time()
        if (current_time - self.file_start_time) > self.rotate_interval:
            return True
        
        return False
    
    def _rotate_file(self):
        """Rotate to a new JSON file"""
        # Create new file name with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"packets_{timestamp}.json"
        self.current_file = self.json_dir / filename
        self.file_start_time = time.time()
        
        logger.info(f"Rotated to new JSON file: {self.current_file}")
        
        # Clean up old files if needed
        self._cleanup_old_files()
    
    def _cleanup_old_files(self):
        """Clean up old JSON files based on max_files setting"""
        if self.max_files <= 0:
            return
        
        # Get list of JSON files sorted by modification time (oldest first)
        json_files = sorted(
            self.json_dir.glob("*.json"),
            key=lambda x: x.stat().st_mtime
        )
        
        # Remove oldest files if we have too many
        while len(json_files) > self.max_files:
            oldest_file = json_files.pop(0)
            try:
                oldest_file.unlink()
                logger.info(f"Deleted old JSON file: {oldest_file}")
            except Exception as e:
                logger.error(f"Error deleting old JSON file {oldest_file}: {e}")