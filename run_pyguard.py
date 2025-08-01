"""
PyGuard Main Runner
This script runs all PyGuard components together.
"""

import sys
import logging
import yaml
import subprocess
import time
import threading
import os
import signal

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load configuration
def load_config():
    try:
        with open('config.yaml', 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return None

# Run a component in a separate process
def run_component(component_name, script_path, stop_event):
    try:
        logger.info(f"Starting {component_name}...")
        process = subprocess.Popen([sys.executable, script_path])
        
        # Wait for process to complete or stop event
        while process.poll() is None and not stop_event.is_set():
            time.sleep(0.1)
        
        # Terminate process if still running
        if process.poll() is None:
            logger.info(f"Stopping {component_name}...")
            process.terminate()
            process.wait(timeout=5)
            
            # Force kill if still running
            if process.poll() is None:
                logger.info(f"Force killing {component_name}...")
                if sys.platform == 'win32':
                    process.kill()
                else:
                    os.kill(process.pid, signal.SIGKILL)
        
        logger.info(f"{component_name} stopped")
    
    except Exception as e:
        logger.error(f"Error running {component_name}: {e}")

# Run flow generator periodically
def run_flow_generator(script_path, interval, stop_event):
    try:
        logger.info(f"Starting flow generator with interval {interval} seconds...")
        
        while not stop_event.is_set():
            # Run flow generator
            subprocess.run([sys.executable, script_path], check=True)
            
            # Wait for next interval or stop event
            for _ in range(int(interval * 10)):  # Check stop event every 0.1 seconds
                if stop_event.is_set():
                    break
                time.sleep(0.1)
        
        logger.info("Flow generator stopped")
    
    except Exception as e:
        logger.error(f"Error running flow generator: {e}")

def main():
    # Load configuration
    config = load_config()
    if not config:
        logger.error("Failed to load configuration")
        return 1
    
    # Create stop event
    stop_event = threading.Event()
    
    # Create threads for each component
    threads = []
    
    # Packet capture thread
    capture_thread = threading.Thread(
        target=run_component,
        args=("packet capture", "capture_traffic.py", stop_event)
    )
    threads.append(capture_thread)
    
    # Flow generator thread
    flow_interval = config.get('flow_interval', 10)  # Default 10 seconds
    flow_thread = threading.Thread(
        target=run_flow_generator,
        args=("generate_flows.py", flow_interval, stop_event)
    )
    threads.append(flow_thread)
    
    # Dashboard thread
    dashboard_thread = threading.Thread(
        target=run_component,
        args=("dashboard", "dashboard.py", stop_event)
    )
    threads.append(dashboard_thread)
    
    try:
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for keyboard interrupt
        while True:
            time.sleep(0.1)
    
    except KeyboardInterrupt:
        logger.info("Stopping PyGuard...")
        
        # Set stop event
        stop_event.set()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        logger.info("PyGuard stopped")
        return 0
    
    except Exception as e:
        logger.error(f"Error: {e}")
        
        # Set stop event
        stop_event.set()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        return 1

if __name__ == "__main__":
    sys.exit(main())