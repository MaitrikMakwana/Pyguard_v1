"""
System resource monitoring module
"""

import os
import time
import logging
import threading
import psutil

logger = logging.getLogger(__name__)

class SystemMonitor:
    """Monitor system resources (CPU, memory) and provide alerts"""
    
    def __init__(self, memory_limit=80, cpu_limit=90, check_interval=10):
        """Initialize system monitor with resource limits"""
        self.memory_limit = memory_limit  # Percentage
        self.cpu_limit = cpu_limit  # Percentage
        self.check_interval = check_interval  # Seconds
        
        self.current_memory_percent = 0
        self.current_cpu_percent = 0
        self.process = psutil.Process(os.getpid())
        
        self.running = False
        self.monitor_thread = None
        self.lock = threading.Lock()
    
    def start(self):
        """Start system monitoring"""
        if self.running:
            logger.warning("System monitor already running")
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("System monitor started")
    
    def stop(self):
        """Stop system monitoring"""
        if not self.running:
            return
        
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        logger.info("System monitor stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Update system resource usage
                self._update_resource_usage()
                
                # Check for resource limits
                self._check_resource_limits()
                
                # Sleep for the check interval
                time.sleep(self.check_interval)
            
            except Exception as e:
                logger.error(f"Error in system monitor: {e}")
                time.sleep(1)  # Avoid tight error loop
    
    def _update_resource_usage(self):
        """Update current resource usage"""
        with self.lock:
            # Get memory usage
            self.current_memory_percent = psutil.virtual_memory().percent
            
            # Get CPU usage
            self.current_cpu_percent = psutil.cpu_percent(interval=0.1)
            
            # Get process-specific info
            self.process_memory_percent = self.process.memory_percent()
            self.process_cpu_percent = self.process.cpu_percent(interval=0.1)
    
    def _check_resource_limits(self):
        """Check if resource usage exceeds limits"""
        with self.lock:
            # Check memory usage
            if self.current_memory_percent > self.memory_limit:
                logger.warning(
                    f"System memory usage ({self.current_memory_percent}%) "
                    f"exceeds limit ({self.memory_limit}%)"
                )
            
            # Check CPU usage
            if self.current_cpu_percent > self.cpu_limit:
                logger.warning(
                    f"System CPU usage ({self.current_cpu_percent}%) "
                    f"exceeds limit ({self.cpu_limit}%)"
                )
            
            # Log process-specific info
            logger.debug(
                f"Process resources: Memory={self.process_memory_percent:.1f}%, "
                f"CPU={self.process_cpu_percent:.1f}%"
            )
    
    def is_overloaded(self):
        """Check if system is overloaded"""
        with self.lock:
            return (
                self.current_memory_percent > self.memory_limit or
                self.current_cpu_percent > self.cpu_limit
            )
    
    def get_current_load(self):
        """Get current system load"""
        with self.lock:
            return {
                "memory_percent": self.current_memory_percent,
                "cpu_percent": self.current_cpu_percent,
                "process_memory_percent": getattr(self, "process_memory_percent", 0),
                "process_cpu_percent": getattr(self, "process_cpu_percent", 0)
            }