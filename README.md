
# PyGuard - Modern Network Traffic Metadata Capture & Analysis

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Virtual Environment](https://img.shields.io/badge/Virtual%20Environment-✅-green.svg)](https://docs.python.org/3/library/venv.html)

PyGuard is a comprehensive desktop application for capturing, analyzing, and storing network traffic metadata. It features a modern PyQt5 UI with sidebar navigation, real-time protocol stats, advanced filtering, and color-coded packet tables. **Now with full virtual environment support and easy launching!**

## 🚀 **Quick Start**

```bash
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Start the application
python run_pyguard.py
```

## ✨ **Features**

- **🚀 High-Performance Packet Capture**: Efficient capture using Scapy and optimized processing
- **📊 Comprehensive Metadata Extraction**: IP, ports, protocols, timestamps, flags, app-layer data, MAC, ICMP, ARP
- **💾 Flexible Storage**: PCAP files, PostgreSQL database, CSV/Parquet export, JSON storage
- **⚡ Scalable Architecture**: Multi-threaded, async storage, efficient memory management
- **🖥️ System Resource Monitoring**: Real-time CPU/memory stats with alerts
- **🎨 Modern Desktop UI**:
  - Sidebar navigation (Capture, Settings, Statistics)
  - Color-coded, sortable packet tables
  - Integrated Machine Learning IDS Analysis (Normal vs Attack traffic)
- **🔒 Virtual Environment**: Fully isolated dependencies
- **📱 Easy Launching**: Clean, single-file entrypoint

## 🏗️ **Project Structure**

```
PyGuard-main/
├── 📁 config/                         # Configuration settings
├── 📁 debug/                          # Sandbox and test scripts
├── 📁 desktop_app/                    # Desktop application UI & logic
├── 📁 docs/                           # Documentation
├── 📁 examples/                       # Sample captures and files
├── 📁 Final_IDS/                      # Integrated ML Pipeline
├── 📁 pyguard/                        # Core PyGuard packet processing
├── 📁 scripts/                        # Utility scripts and processors
├── 📁 tests/                          # Automated tests
├── 🚀 run_pyguard.py                  # Main application entry point
└── 📋 requirements.txt                # Python dependencies
```

## 🔧 **Requirements**

- **Python**: 3.8 or higher
- **Operating System**: Windows 10/11, Linux, macOS
- **System Dependencies**:
  - **Windows**: [Npcap](https://npcap.com/#download) for packet capture
  - **Linux**: `sudo apt-get install libpcap-dev`
  - **macOS**: `brew install libpcap`

## 🚀 **Installation & Setup**

### **1. Clone the Repository**
```bash
git clone https://github.com/yourusername/pyguard.git
cd pyguard
```

### **2. Launch The App**
```bash
# 1. Activate your virtual environment
.\venv\Scripts\Activate.ps1

# 2. Run the launcher
python run_pyguard.py
```

## 🎯 **Usage**

### **Desktop Application**
1. **Launch**: `python run_pyguard.py`
2. **Interface Selection**: Choose your network interface.
3. **Start Capture**: Click "Start Capture" button.
4. **Monitor**: Watch real-time packet analysis and statistics.
5. **IDS Analysis**: Use the ML tab to detect malicious flows from captured PCAPs.

## ⚙️ **Configuration**

Edit `config/config.yaml` for custom settings:

```yaml
version: 0.1.0
interface: auto                    # Network interface selection
output_dir: ./output              # Output directory
pcap:
  enabled: true                   # Enable PCAP file storage
```

## 🧪 **Testing**

Run the test suite to verify your setup:

```bash
.\venv\Scripts\Activate.ps1
python -m pytest tests/
```

## 🤝 **Contributing**

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**🚀 PyGuard is ready to use! Choose your preferred launch method and start capturing network traffic!**