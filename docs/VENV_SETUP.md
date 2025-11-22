# PyGuard Virtual Environment Setup

## ✅ What's Working

Your PyGuard project is now successfully set up in a virtual environment with the following working components:

- **Core PyGuard package** - Basic structure and imports
- **Storage modules** - CSV and JSON storage functionality
- **System monitoring** - System resource monitoring
- **Data processing** - Pandas, NumPy, PyArrow
- **GUI framework** - PyQt5 for desktop applications
- **Network analysis** - Scapy for packet analysis (basic functionality)

## ⚠️ What Needs Attention

Some modules require compilation and may not work without additional tools:

- **`pcapy-ng`** - Packet capture library (needs Microsoft Visual C++ Build Tools)
- **`netifaces`** - Network interface detection (needs Microsoft Visual C++ Build Tools)

## 🚀 How to Use

### Option 1: Quick Start (Recommended)
Double-click `activate_and_run.bat` or run `activate_and_run.ps1` in PowerShell.

### Option 2: Manual Activation
```bash
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Run the project
python run_in_venv.py
```

### Option 3: Test Individual Components
```bash
# Test basic functionality
python test_venv.py

# Run specific scripts
python scripts/demo_complete_workflow.py
```

## 🔧 Full Functionality Setup

To enable packet capture and network interface detection:

1. **Install Microsoft Visual C++ Build Tools:**
   - Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
   - Install with C++ build tools workload

2. **Reinstall problematic packages:**
   ```bash
   pip install pcapy-ng netifaces
   ```

## 📁 Project Structure

```
PyGuard-main/
├── venv/                    # Virtual environment
├── pyguard/                 # Main package
├── desktop_app/            # Desktop application
├── scripts/                # Utility scripts
├── test_venv.py           # Virtual environment test
├── run_in_venv.py         # Main launcher
├── activate_and_run.bat    # Windows batch launcher
├── activate_and_run.ps1    # PowerShell launcher
└── VENV_SETUP.md          # This file
```

## 🧪 Testing

Run the test script to verify your setup:
```bash
python test_venv.py
```

## 💡 Troubleshooting

### Common Issues:

1. **"Microsoft Visual C++ 14.0 required"**
   - Install Microsoft Visual C++ Build Tools
   - Or use the working modules only

2. **Import errors for pcapy/netifaces**
   - These are optional for basic functionality
   - Use Scapy as an alternative for packet analysis

3. **Virtual environment not activating**
   - Ensure you're in the correct directory
   - Use the provided batch/PowerShell scripts

## 🎯 Next Steps

1. **Test basic functionality** with `test_venv.py`
2. **Run the launcher** with `run_in_venv.py`
3. **Explore working modules** (storage, system monitoring)
4. **Install build tools** if you need full packet capture functionality

## 📞 Support

If you encounter issues:
1. Check the test output from `test_venv.py`
2. Verify your Python version (3.8+ recommended)
3. Ensure all dependencies are installed in the virtual environment

---

**Status: ✅ Virtual Environment Ready - Basic Functionality Available**
