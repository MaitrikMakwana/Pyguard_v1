---
description: Repository Information Overview
alwaysApply: true
---

# PyGuard Information

## Summary
PyGuard is a high-performance network traffic metadata capture and analysis application. It features packet capture capabilities, comprehensive metadata extraction, flexible storage options, and a modern desktop UI built with PyQt5. The application can run in both GUI and headless modes, making it suitable for various network monitoring scenarios.

## Structure
- **pyguard/**: Core package containing the main application modules
  - **core/**: Core functionality (packet capture, processing, configuration)
  - **storage/**: Storage modules for different data formats (database, CSV, JSON)
  - **ui/**: User interface components
  - **utils/**: Utility functions and system monitoring
- **desktop_app/**: Desktop application with advanced UI features
- **scripts/**: Utility scripts for setup and maintenance
- **tests/**: Unit tests for core functionality

## Language & Runtime
**Language**: Python
**Version**: 3.8 or higher
**Build System**: setuptools
**Package Manager**: pip

## Dependencies
**Main Dependencies**:
- scapy (≥2.5.0): Network packet manipulation
- pcapy-ng (≥1.0.9): High-performance packet capture
- PyQt5 (≥5.15.7): GUI framework
- psutil (≥5.9.0): System resource monitoring
- sqlalchemy (≥2.0.0): Database ORM
- psycopg2-binary (≥2.9.5): PostgreSQL driver
- PyYAML (≥6.0): Configuration file parsing
- pandas (≥1.5.0): Data manipulation
- pyarrow (≥10.0.0): Efficient data storage

**System Dependencies**:
- Windows: Npcap
- Linux: libpcap-dev
- macOS: libpcap

## Build & Installation
```bash
# Install system dependencies first (Npcap on Windows, libpcap on Linux/macOS)
# Clone repository
git clone https://github.com/yourusername/pyguard.git
cd pyguard

# Create virtual environment (optional)
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

## Usage
**Desktop Application**:
```bash
# Run the desktop application
python desktop_app/run_desktop_app.py
```

**Core Application**:
```bash
# Run with GUI
python -m pyguard.main

# Run in headless mode
python -m pyguard.main --no-gui --interface eth0 --output-dir /path/to/output
```

## Configuration
PyGuard uses a YAML configuration file (`config.yaml`) with the following key sections:
- **Interface**: Network interface to capture from
- **Output**: Directory for storing output files
- **PCAP**: Settings for packet capture files (rotation, size limits)
- **Database**: PostgreSQL connection settings
- **CSV Export**: Settings for exporting data to CSV files
- **Capture**: Packet capture settings (BPF filter, promiscuous mode)
- **System**: Resource monitoring limits

## Core Components

### Packet Capture
The `packet_capture.py` module handles raw packet capture using pcapy-ng. It:
- Captures packets from network interfaces
- Applies BPF filters
- Manages PCAP file rotation
- Monitors system resources to prevent overload

### Packet Processing
The `packet_processor.py` module extracts metadata from captured packets:
- Parses network protocols (Ethernet, IP, TCP, UDP, etc.)
- Extracts application-layer data (HTTP, DNS, TLS, etc.)
- Generates protocol trees and packet summaries
- Supports deep packet inspection

### Storage
Multiple storage backends are supported:
- **database_storage.py**: PostgreSQL storage via SQLAlchemy
- **csv_storage.py**: CSV/Parquet file export
- **json_storage.py**: JSON file storage

### Desktop UI
The desktop application provides a modern interface with:
- Sidebar navigation (Capture, Settings, Statistics)
- Real-time protocol statistics
- Color-coded packet tables
- Advanced filtering capabilities
- System resource monitoring

## Testing
The project includes unit tests for core functionality:
- **test_packet_processor.py**: Tests for packet metadata extraction
- **test_config.py**: Tests for configuration handling
- **test_system_monitor.py**: Tests for system resource monitoring

Run tests with:
```bash
pytest tests/
```