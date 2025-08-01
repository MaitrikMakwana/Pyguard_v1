"""
Configuration management for PyGuard
"""

import os
import yaml
from pathlib import Path
import logging
import netifaces

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "version": "0.2.0",
    "interface": None,  # Will be auto-detected if not specified
    "interfaces": [],   # For multi-interface support
    "output_dir": "./output",
    "pcap": {
        "enabled": True,
        "rotate_size_mb": 100,
        "rotate_interval_minutes": 60,
        "max_files": 10
    },
    "database": {
        "enabled": True,
        "type": "postgresql",
        "host": "localhost",
        "port": 5432,
        "name": "pyguard",
        "user": "postgres",
        "password": "postgres",
        "batch_size": 1000,
        "commit_interval": 5  # seconds
    },
    "csv_export": {
        "enabled": False,
        "directory": "./csv_export",
        "rotate_interval_minutes": 60,
        "max_files": 10
    },
    "json_export": {
        "enabled": False,
        "directory": "./json_export",
        "rotate_interval_minutes": 60,
        "max_files": 10,
        "pretty_print": True
    },
    "capture": {
        "bpf_filter": "",  # Empty string means capture everything
        "snaplen": 65535,  # Maximum packet size to capture
        "promiscuous": True,
        "buffer_size_mb": 100,
        "batch_size": 1000,
        "processing_threads": 4,
        "async_mode": True,  # Use asynchronous I/O for better performance
        "sampling_rate": 1.0,  # 1.0 means capture all packets, 0.5 means capture 50% of packets
        "deep_inspection": True,  # Enable deep protocol inspection
        "extract_payload": False  # Whether to extract and store packet payloads
    },
    "display": {
        "columns": ["timestamp", "src_ip", "dst_ip", "protocol", "length", "info"],
        "default_filter": "",
        "color_rules": [
            {"protocol": "TCP", "color": "#E6F3FF"},
            {"protocol": "UDP", "color": "#EAFFEA"},
            {"protocol": "ICMP", "color": "#FFECEC"},
            {"protocol": "DNS", "color": "#FFF6E5"},
            {"protocol": "HTTP", "color": "#F9ECFF"}
        ],
        "time_format": "%Y-%m-%d %H:%M:%S.%f",
        "refresh_interval_ms": 1000
    },
    "protocols": {
        "ethernet": True,
        "ip": True,
        "tcp": True,
        "udp": True,
        "icmp": True,
        "arp": True,
        "dns": True,
        "http": True,
        "https": True,
        "tls": True,
        "smtp": True,
        "ftp": True,
        "ssh": True,
        "telnet": True,
        "ntp": True,
        "snmp": True,
        "dhcp": True
    },
    "system": {
        "memory_limit_percent": 80,
        "cpu_limit_percent": 90,
        "check_interval_seconds": 10
    },
    "log_level": "INFO",
    "log_file": "pyguard.log"
}

class Config:
    """Configuration class for PyGuard"""
    
    def __init__(self, config_path=None):
        """Initialize configuration with default values and load from file if provided"""
        # Start with default configuration
        self._config = DEFAULT_CONFIG.copy()
        
        # Load configuration from file if provided
        if config_path and os.path.exists(config_path):
            self._load_from_file(config_path)
        
        # Auto-detect interface if not specified
        if not self.interface:
            self.interface = self._auto_detect_interface()
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Create CSV export directory if enabled
        if self.csv_export["enabled"]:
            os.makedirs(self.csv_export["directory"], exist_ok=True)
    
    def _load_from_file(self, config_path):
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                
            # Update default config with user config (recursive)
            self._update_config(self._config, user_config)
            logger.info(f"Loaded configuration from {config_path}")
        except Exception as e:
            logger.error(f"Error loading configuration from {config_path}: {e}")
    
    def _update_config(self, default_config, user_config):
        """Recursively update default config with user config"""
        if not user_config:
            return
            
        for key, value in user_config.items():
            if key in default_config:
                if isinstance(value, dict) and isinstance(default_config[key], dict):
                    self._update_config(default_config[key], value)
                else:
                    default_config[key] = value
    
    def _auto_detect_interface(self):
        """Auto-detect the default network interface"""
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                return gateways['default'][netifaces.AF_INET][1]
            
            # If no default gateway, return the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface.lower() != 'loopback':
                    return interface
            
            # If all else fails, return loopback
            return 'lo' if 'lo' in netifaces.interfaces() else 'loopback'
        except Exception as e:
            logger.error(f"Error auto-detecting network interface: {e}")
            return 'eth0'  # Fallback to a common interface name
    
    def save(self, config_path):
        """Save current configuration to file"""
        try:
            with open(config_path, 'w') as f:
                yaml.dump(self._config, f, default_flow_style=False)
            logger.info(f"Saved configuration to {config_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving configuration to {config_path}: {e}")
            return False
    
    def __getattr__(self, name):
        """Get configuration value by attribute name"""
        if name in self._config:
            return self._config[name]
        raise AttributeError(f"Configuration has no attribute '{name}'")
    
    def __setattr__(self, name, value):
        """Set configuration value by attribute name"""
        if name == '_config':
            super().__setattr__(name, value)
        elif name in self._config:
            self._config[name] = value
        else:
            raise AttributeError(f"Configuration has no attribute '{name}'")
    
    def get(self, key, default=None):
        """Get configuration value by key with default fallback"""
        return self._config.get(key, default)