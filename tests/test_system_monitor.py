"""
Tests for the system monitor module
"""

import unittest
from unittest.mock import patch, MagicMock
import time

from pyguard.utils.system_monitor import SystemMonitor

class TestSystemMonitor(unittest.TestCase):
    """Test cases for the SystemMonitor class"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a system monitor with test limits
        self.monitor = SystemMonitor(
            memory_limit=90,
            cpu_limit=80,
            check_interval=0.1
        )
    
    def tearDown(self):
        """Clean up test environment"""
        if self.monitor.running:
            self.monitor.stop()
    
    @patch('psutil.virtual_memory')
    @patch('psutil.cpu_percent')
    @patch('psutil.Process')
    def test_update_resource_usage(self, mock_process, mock_cpu_percent, mock_virtual_memory):
        """Test updating resource usage"""
        # Mock psutil functions
        mock_virtual_memory.return_value = MagicMock(percent=75.0)
        mock_cpu_percent.return_value = 65.0
        
        mock_process_instance = MagicMock()
        mock_process_instance.memory_percent.return_value = 30.0
        mock_process_instance.cpu_percent.return_value = 25.0
        mock_process.return_value = mock_process_instance
        
        # Update resource usage
        self.monitor._update_resource_usage()
        
        # Check that values were updated
        self.assertEqual(self.monitor.current_memory_percent, 75.0)
        self.assertEqual(self.monitor.current_cpu_percent, 65.0)
        self.assertEqual(self.monitor.process_memory_percent, 30.0)
        self.assertEqual(self.monitor.process_cpu_percent, 25.0)
    
    @patch('psutil.virtual_memory')
    @patch('psutil.cpu_percent')
    def test_is_overloaded(self, mock_cpu_percent, mock_virtual_memory):
        """Test checking if system is overloaded"""
        # Test case: not overloaded
        mock_virtual_memory.return_value = MagicMock(percent=75.0)
        mock_cpu_percent.return_value = 65.0
        
        self.monitor._update_resource_usage()
        self.assertFalse(self.monitor.is_overloaded())
        
        # Test case: memory overloaded
        mock_virtual_memory.return_value = MagicMock(percent=95.0)
        mock_cpu_percent.return_value = 65.0
        
        self.monitor._update_resource_usage()
        self.assertTrue(self.monitor.is_overloaded())
        
        # Test case: CPU overloaded
        mock_virtual_memory.return_value = MagicMock(percent=75.0)
        mock_cpu_percent.return_value = 85.0
        
        self.monitor._update_resource_usage()
        self.assertTrue(self.monitor.is_overloaded())
        
        # Test case: both overloaded
        mock_virtual_memory.return_value = MagicMock(percent=95.0)
        mock_cpu_percent.return_value = 85.0
        
        self.monitor._update_resource_usage()
        self.assertTrue(self.monitor.is_overloaded())
    
    @patch('psutil.virtual_memory')
    @patch('psutil.cpu_percent')
    @patch('psutil.Process')
    def test_get_current_load(self, mock_process, mock_cpu_percent, mock_virtual_memory):
        """Test getting current system load"""
        # Mock psutil functions
        mock_virtual_memory.return_value = MagicMock(percent=75.0)
        mock_cpu_percent.return_value = 65.0
        
        mock_process_instance = MagicMock()
        mock_process_instance.memory_percent.return_value = 30.0
        mock_process_instance.cpu_percent.return_value = 25.0
        mock_process.return_value = mock_process_instance
        
        # Update resource usage
        self.monitor._update_resource_usage()
        
        # Get current load
        load = self.monitor.get_current_load()
        
        # Check load values
        self.assertEqual(load["memory_percent"], 75.0)
        self.assertEqual(load["cpu_percent"], 65.0)
        self.assertEqual(load["process_memory_percent"], 30.0)
        self.assertEqual(load["process_cpu_percent"], 25.0)
    
    @patch('threading.Thread')
    def test_start_stop(self, mock_thread):
        """Test starting and stopping the monitor"""
        # Mock Thread.start
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance
        
        # Start monitor
        self.monitor.start()
        
        # Check that monitor is running
        self.assertTrue(self.monitor.running)
        mock_thread_instance.start.assert_called_once()
        
        # Stop monitor
        self.monitor.stop()
        
        # Check that monitor is stopped
        self.assertFalse(self.monitor.running)
        mock_thread_instance.join.assert_called_once()

if __name__ == "__main__":
    unittest.main()