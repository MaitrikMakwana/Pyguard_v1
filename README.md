
# PyGuard - Modern Network Traffic Metadata Capture & Analysis

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Virtual Environment](https://img.shields.io/badge/Virtual%20Environment-✅-green.svg)](https://docs.python.org/3/library/venv.html)

PyGuard is a comprehensive desktop application for capturing, analyzing, and storing network traffic metadata. It features a modern PyQt5 UI with sidebar navigation, real-time protocol stats, advanced filtering, and color-coded packet tables. **Now with full virtual environment support and easy launching!**

## 🚀 **Quick Start**

### **Option 1: Double-click Launch (Easiest)**
```bash
# Simply double-click this file:
desktop_app\run_desktop_app.bat
```

### **Option 2: PowerShell Launch**
```bash
# Activate virtual environment and run:
.\venv\Scripts\Activate.ps1
python desktop_app\run_desktop_app.py
```

### **Option 3: Main Application**
```bash
# Activate virtual environment and run main app:
.\venv\Scripts\Activate.ps1
python run_in_venv.py
```

## ✨ **Features**

- **🚀 High-Performance Packet Capture**: Efficient capture using Scapy and optimized processing
- **📊 Comprehensive Metadata Extraction**: IP, ports, protocols, timestamps, flags, app-layer data, MAC, ICMP, ARP
- **💾 Flexible Storage**: PCAP files, PostgreSQL database, CSV/Parquet export, JSON storage
- **⚡ Scalable Architecture**: Multi-threaded, async storage, efficient memory management
- **🖥️ System Resource Monitoring**: Real-time CPU/memory stats with alerts
- **🎨 Modern Desktop UI**:
  - Sidebar navigation (Capture, Settings, Statistics)
  - Right-side tabs for Packet Analysis, Captured Packets, Advanced Filter, Info
  - Color-coded, sortable packet table
  - Collapsible log viewer
  - Dark/light mode switching
  - Tooltips and responsive layout
- **🔒 Virtual Environment**: Fully isolated dependencies, no system conflicts
- **📱 Easy Launching**: Multiple launcher options for different use cases

## 🏗️ **Project Structure**

```
PyGuard-main/
├── 📁 venv/                           # Virtual environment (isolated dependencies)
├── 📁 pyguard/                        # Core PyGuard package
│   ├── 📁 core/                       # Core functionality
│   │   ├── capture_manager.py         # Capture coordination
│   │   ├── packet_capture.py          # Packet capture engine
│   │   ├── packet_processor.py        # Packet processing & analysis
│   │   └── config.py                  # Configuration management
│   ├── 📁 storage/                    # Data storage modules
│   │   ├── csv_storage.py             # CSV export functionality
│   │   ├── database_storage.py        # PostgreSQL database storage
│   │   └── json_storage.py            # JSON file storage
│   ├── 📁 ui/                         # User interface
│   │   └── app.py                     # Main UI application
│   ├── 📁 utils/                      # Utility modules
│   │   └── system_monitor.py          # System resource monitoring
│   └── main.py                        # Main application entry point
├── 📁 desktop_app/                    # Desktop application
│   ├── desktop_app.py                 # Main desktop app (PyQt5)
│   ├── run_desktop_app.py             # Enhanced launcher with VE support
│   ├── run_desktop_app.bat            # Windows batch launcher
│   └── __init__.py                    # Package initialization
├── 📁 scripts/                        # Utility scripts
│   ├── capture_traffic.py             # Traffic capture utilities
│   ├── flow_analyzer.py               # Flow analysis tools
│   ├── ml_workflow.py                 # Machine learning pipeline
│   └── setup_database.py              # Database setup
├── 📁 config/                         # Configuration files
│   └── config.yaml                    # Main configuration
├── 📁 examples/                       # Example files
│   └── test4949.pcap                  # Sample PCAP file
├── 📁 tests/                          # Test suite
├── 📁 docs/                           # Documentation
├── 🚀 run_in_venv.py                  # Main virtual environment launcher
├── 🚀 activate_and_run.bat            # Windows batch launcher
├── 🚀 activate_and_run.ps1            # PowerShell launcher
├── 📋 requirements.txt                 # Python dependencies
├── 📋 setup.py                        # Package setup
└── 📋 README.md                       # This file
```

## 🔧 **Requirements**

- **Python**: 3.8 or higher
- **Operating System**: Windows 10/11, Linux, macOS
- **System Dependencies**:
  - **Windows**: [Npcap](https://npcap.com/#download) for packet capture
  - **Linux**: `sudo apt-get install libpcap-dev`
  - **macOS**: `brew install libpcap`
- **Virtual Environment**: Automatically created and managed

## 🚀 **Installation & Setup**

### **1. Clone the Repository**
```bash
git clone https://github.com/yourusername/pyguard.git
cd pyguard
```

### **2. Virtual Environment Setup (Automatic)**
The project is already set up with a virtual environment! No additional setup needed.

**What's Already Done:**
- ✅ Virtual environment created (`venv/`)
- ✅ All dependencies installed in isolated environment
- ✅ PyQt5, Scapy, Pandas, and other packages ready
- ✅ No conflicts with system Python

### **3. Launch Options**

#### **🚀 Desktop App (Recommended)**
```bash
# Double-click this file:
desktop_app\run_desktop_app.bat
```

#### **🚀 Main Application**
```bash
# Double-click this file:
activate_and_run.bat
```

#### **🚀 PowerShell**
```bash
# Activate and run:
.\venv\Scripts\Activate.ps1
python run_in_venv.py
```

## 🎯 **Usage**

### **Desktop Application**
1. **Launch**: Double-click `desktop_app\run_desktop_app.bat`
2. **Interface Selection**: Choose your network interface
3. **Start Capture**: Click "Start Capture" button
4. **Monitor**: Watch real-time packet analysis and statistics
5. **Export**: Save data to CSV, JSON, or database

### **Main Application**
1. **Launch**: Use `activate_and_run.bat` or PowerShell
2. **Configuration**: Edit `config/config.yaml` for custom settings
3. **Capture**: Start packet capture with your preferred settings
4. **Analysis**: View detailed packet analysis and flow statistics

### **Command Line Scripts**
```bash
# Activate virtual environment first
.\venv\Scripts\Activate.ps1

# Run specific scripts
python scripts/capture_traffic.py
python scripts/flow_analyzer.py
python scripts/ml_workflow.py
```

## ⚙️ **Configuration**

Edit `config/config.yaml` for custom settings:

```yaml
version: 0.1.0
interface: auto                    # Network interface selection
output_dir: ./output              # Output directory
pcap:
  enabled: true                   # Enable PCAP file storage
  rotate_size_mb: 100            # File rotation size
  max_files: 10                  # Maximum files to keep
database:
  enabled: true                   # Enable database storage
  type: postgresql                # Database type
  host: localhost                 # Database host
  port: 5432                      # Database port
  name: pyguard                   # Database name
capture:
  bpf_filter: ""                  # Berkeley Packet Filter
  snaplen: 65535                  # Capture length
  promiscuous: true               # Promiscuous mode
  buffer_size_mb: 100            # Buffer size
system:
  memory_limit_percent: 80        # Memory usage limit
  cpu_limit_percent: 90          # CPU usage limit
log_level: INFO                   # Logging level
```

## 🏗️ **Architecture**

PyGuard uses a modular, scalable architecture:

### **Core Components**
- **📡 Packet Capture**: Scapy-based capture with interface detection
- **⚙️ Processing Engine**: Multi-threaded packet analysis and metadata extraction
- **💾 Storage Layer**: Multiple storage backends (CSV, JSON, PostgreSQL)
- **🖥️ UI Framework**: PyQt5-based desktop application
- **📊 Monitoring**: Real-time system resource and capture statistics

### **Data Flow**
```
Network Interface → Packet Capture → Processing → Storage → Analysis → UI
```

### **Performance Features**
- **🚀 Async Processing**: Non-blocking packet processing
- **📊 Batch Operations**: Efficient database and file operations
- **💾 Memory Management**: Smart buffer management and rotation
- **🔄 Multi-threading**: Parallel packet processing and storage

## 🧪 **Testing**

Run the test suite to verify your setup:

```bash
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Run tests
python -m pytest tests/
```

## 🔍 **Troubleshooting**

### **Common Issues**

#### **1. PyQt5 Import Error**
```bash
# Solution: Use the virtual environment
.\venv\Scripts\Activate.ps1
python desktop_app\run_desktop_app.py
```

#### **2. Packet Capture Issues**
- Ensure Npcap is installed (Windows)
- Check interface permissions
- Verify network interface is active

#### **3. Database Connection**
- PostgreSQL service running
- Correct credentials in `config.yaml`
- Database created and accessible

### **Getting Help**
1. Check the logs in the application
2. Verify virtual environment is active
3. Review `config/config.yaml` settings
4. Check system requirements

## 📚 **Documentation**

- **📋 VENV_SETUP.md**: Virtual environment setup guide
- **📋 GLOBAL_CLEANUP_SUMMARY.md**: Package cleanup details
- **📋 DESKTOP_APP_FIX_SUMMARY.md**: Desktop app troubleshooting
- **📋 PROJECT_STRUCTURE.md**: Detailed project organization
- **📋 USAGE.md**: Comprehensive usage guide

## 🤝 **Contributing**

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 **Acknowledgments**

- [Scapy](https://scapy.net/) - Packet manipulation and analysis
- [PyQt5](https://www.riverbankcomputing.com/software/pyqt/) - Desktop GUI framework
- [Pandas](https://pandas.pydata.org/) - Data manipulation and analysis
- [SQLAlchemy](https://www.sqlalchemy.org/) - Database operations
- [psutil](https://psutil.readthedocs.io/) - System monitoring

## 🎉 **Status**

- ✅ **Virtual Environment**: Fully configured and isolated
- ✅ **Dependencies**: All packages installed and working
- ✅ **Desktop App**: PyQt5 integration complete
- ✅ **Launch Options**: Multiple easy-launch methods
- ✅ **Documentation**: Comprehensive guides and troubleshooting
- ✅ **Testing**: Verified functionality across components

---

**🚀 PyGuard is ready to use! Choose your preferred launch method and start capturing network traffic!**