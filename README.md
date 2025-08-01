
# PyGuard - Modern Network Traffic Metadata Capture & Analysis

PyGuard is a desktop application for capturing, analyzing, and storing network traffic metadata. It features a modern PyQt6 UI with sidebar navigation, real-time protocol stats, advanced filtering, and color-coded packet tables.

## Features

- **High-Performance Packet Capture**: Efficient capture and processing using pcapy-ng and scapy
- **Comprehensive Metadata Extraction**: IP, ports, protocols, timestamps, flags, app-layer data, MAC, ICMP, ARP, etc.
- **Flexible Storage**: PCAP files, PostgreSQL database, CSV/Parquet export
- **Scalable Architecture**: Multi-threaded, async storage, efficient memory management
- **System Resource Monitoring**: Real-time CPU/memory stats
- **Modern Desktop UI**:
  - Sidebar navigation (Capture, Settings, Statistics)
  - Right-side tabs for Packet Analysis, Captured Packets, Advanced Filter, Info
  - Color-coded, sortable packet table
  - Collapsible log viewer
  - Dark/light mode switching
  - Tooltips and responsive layout

## Requirements

- Python 3.8 or higher
- PostgreSQL (optional)
- Npcap (Windows) or libpcap (Linux/macOS)
- See `requirements.txt`

## Installation

1. Install system dependencies:
   - **Windows**: [Npcap](https://npcap.com/#download)
   - **Linux**: `sudo apt-get install libpcap-dev`
   - **macOS**: `brew install libpcap`
2. Clone the repo:
   ```bash
   git clone https://github.com/yourusername/pyguard.git
   cd pyguard
   ```
3. (Optional) Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   ```
4. Install Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Desktop App

1. Start the desktop app:
   ```bash
   python desktop_app/run_desktop_app.py
   ```
2. Use the sidebar to switch between Capture, Settings, and Statistics.
3. View captured packets in the left table; analyze details in right-side tabs.

## Configuration

Edit `config.yaml` for custom settings (interface, database, storage, etc).

## Contributing

1. Fork the repo
2. Create a branch
3. Submit a pull request

## License

MIT

## Requirements

- Python 3.8 or higher
- PostgreSQL database (optional, for metadata storage)
- Npcap (Windows) or libpcap (Linux/macOS)
- Required Python packages (see `requirements.txt`)

## Installation

1. Install the required system dependencies:
   - **Windows**: Install [Npcap](https://npcap.com/#download)
   - **Linux**: Install libpcap (`sudo apt-get install libpcap-dev` on Debian/Ubuntu)
   - **macOS**: Install libpcap (`brew install libpcap`)

2. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/pyguard.git
   cd pyguard
   ```

3. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

5. Install the package in development mode:
   ```bash
   pip install -e .
   ```

6. Set up the PostgreSQL database (optional):
   ```bash
   # Create database
   createdb pyguard
   
   # Run schema setup script
   python scripts/setup_database.py
   ```

## Usage

### GUI Mode

1. Start the application:
   ```bash
   python -m pyguard.main
   ```

2. Use the GUI to:
   - Select the network interface to capture from
   - Configure capture settings (BPF filter, promiscuous mode, etc.)
   - Start and stop capture
   - Monitor capture statistics and system resources

### Command Line Mode

1. Start the application in headless mode:
   ```bash
   python -m pyguard.main --no-gui --interface eth0 --output-dir /path/to/output
   ```

2. Additional command line options:
   ```bash
   python -m pyguard.main --help
   ```

## Configuration

PyGuard can be configured using a YAML configuration file. A default configuration is created on first run, which you can modify as needed.

Example configuration:
```yaml
version: 0.1.0
interface: eth0
output_dir: ./output
pcap:
  enabled: true
  rotate_size_mb: 100
  rotate_interval_minutes: 60
  max_files: 10
database:
  enabled: true
  type: postgresql
  host: localhost
  port: 5432
  name: pyguard
  user: postgres
  password: postgres
  batch_size: 1000
  commit_interval: 5
csv_export:
  enabled: false
  directory: ./csv_export
  rotate_interval_minutes: 60
  max_files: 10
capture:
  bpf_filter: ""
  snaplen: 65535
  promiscuous: true
  buffer_size_mb: 100
  batch_size: 1000
  processing_threads: 4
system:
  memory_limit_percent: 80
  cpu_limit_percent: 90
  check_interval_seconds: 10
log_level: INFO
log_file: pyguard.log
```

## Architecture

PyGuard is designed with a modular architecture to ensure scalability and maintainability:

1. **Core Modules**:
   - `packet_capture.py`: Handles raw packet capture using pcapy-ng
   - `packet_processor.py`: Extracts metadata from captured packets
   - `capture_manager.py`: Coordinates capture and processing workflows
   - `config.py`: Manages application configuration

2. **Storage Modules**:
   - `database_storage.py`: Stores metadata in PostgreSQL database
   - `csv_storage.py`: Exports metadata to CSV/Parquet files

3. **UI Modules**:
   - `app.py`: Provides GUI interface using PyQt5

4. **Utility Modules**:
   - `system_monitor.py`: Monitors system resources

## Performance Considerations

- **Packet Capture**: Uses pcapy-ng for high-performance packet capture
- **Processing**: Multi-threaded design for parallel packet processing
- **Storage**: Batch processing and asynchronous storage to prevent blocking
- **Memory Management**: Efficient queue management to prevent memory overuse
- **System Monitoring**: Real-time resource monitoring to prevent system overload

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Scapy](https://scapy.net/) for packet manipulation
- [pcapy-ng](https://github.com/stamparm/pcapy-ng) for packet capture
- [SQLAlchemy](https://www.sqlalchemy.org/) for database operations
- [PyQt5](https://www.riverbankcomputing.com/software/pyqt/) for GUI