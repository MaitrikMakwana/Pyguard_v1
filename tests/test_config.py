"""
Tests for the configuration module
"""

import os
import tempfile
import unittest
from pathlib import Path

from pyguard.core.config import Config, DEFAULT_CONFIG

class TestConfig(unittest.TestCase):
    """Test cases for the Config class"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a temporary directory for test files
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
    
    def tearDown(self):
        """Clean up test environment"""
        self.temp_dir.cleanup()
    
    def test_default_config(self):
        """Test default configuration"""
        config = Config()
        
        # Check that default values are set
        self.assertEqual(config.version, DEFAULT_CONFIG["version"])
        self.assertEqual(config.pcap["enabled"], DEFAULT_CONFIG["pcap"]["enabled"])
        self.assertEqual(config.database["host"], DEFAULT_CONFIG["database"]["host"])
    
    def test_load_from_file(self):
        """Test loading configuration from file"""
        # Create a test configuration file
        config_path = self.temp_path / "test_config.yaml"
        with open(config_path, "w") as f:
            f.write("""
version: 0.2.0
interface: test_interface
database:
  host: test_host
  port: 5433
            """)
        
        # Load configuration from file
        config = Config(config_path)
        
        # Check that values from file are loaded
        self.assertEqual(config.version, "0.2.0")
        self.assertEqual(config.interface, "test_interface")
        self.assertEqual(config.database["host"], "test_host")
        self.assertEqual(config.database["port"], 5433)
        
        # Check that default values are preserved for unspecified options
        self.assertEqual(config.pcap["enabled"], DEFAULT_CONFIG["pcap"]["enabled"])
    
    def test_save_config(self):
        """Test saving configuration to file"""
        # Create a config instance
        config = Config()
        
        # Modify some values
        config.version = "0.2.0"
        config.interface = "test_interface"
        config.database["host"] = "test_host"
        
        # Save to file
        config_path = self.temp_path / "saved_config.yaml"
        config.save(config_path)
        
        # Load the saved file and check values
        loaded_config = Config(config_path)
        self.assertEqual(loaded_config.version, "0.2.0")
        self.assertEqual(loaded_config.interface, "test_interface")
        self.assertEqual(loaded_config.database["host"], "test_host")
    
    def test_attribute_access(self):
        """Test attribute access methods"""
        config = Config()
        
        # Test __getattr__
        self.assertEqual(config.version, DEFAULT_CONFIG["version"])
        
        # Test __setattr__
        config.version = "0.2.0"
        self.assertEqual(config.version, "0.2.0")
        
        # Test get method
        self.assertEqual(config.get("version"), "0.2.0")
        self.assertEqual(config.get("nonexistent", "default"), "default")
        
        # Test attribute error
        with self.assertRaises(AttributeError):
            config.nonexistent = "value"

if __name__ == "__main__":
    unittest.main()