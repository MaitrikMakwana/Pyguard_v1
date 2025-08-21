# PyGuard Project Structure

## Overview
This document describes the clean, organized structure of the PyGuard project after reorganization.

## Directory Structure

```
PyGuard-main/
├── desktop_app/              # Main desktop application
│   ├── desktop_app.py        # Core desktop application
│   ├── run_desktop_app.py    # Desktop app launcher
│   ├── FEATURES_ADDED.md     # Feature documentation
│   ├── README.md             # Desktop app readme
│   └── __pycache__/          # Python cache
│
├── pyguard/                  # Core PyGuard modules
│   ├── __init__.py
│   ├── core/                 # Core functionality
│   │   ├── __init__.py
│   │   ├── packet_capture.py
│   │   ├── packet_processor.py
│   │   ├── capture_manager.py
│   │   └── config.py
│   ├── storage/              # Data storage modules
│   │   ├── __init__.py
│   │   ├── database_storage.py
│   │   ├── csv_storage.py
│   │   └── json_storage.py
│   ├── ui/                   # User interface modules
│   │   ├── __init__.py
│   │   └── app.py
│   └── utils/                # Utility modules
│       ├── __init__.py
│       └── system_monitor.py
│
├── tests/                    # Test files
│   ├── test_stop_button.py
│   ├── test_unicode_csv.py
│   ├── test_final_csv_fix.py
│   ├── test_packet_extraction.py
│   ├── test_csv_export.py
│   └── test_csv_to_flows.py
│
├── scripts/                  # Utility scripts
│   ├── run_flow_analysis.py
│   ├── pcap_to_flows.py
│   ├── ml_flow_converter.py
│   ├── flow_analyzer.py
│   ├── demo_complete_workflow.py
│   ├── csv_to_flows.py
│   ├── debug_csv_issue.py
│   ├── capture_traffic.py
│   ├── complete_workflow_demo.py
│   ├── capture_to_csv.py
│   ├── complete_ml_pipeline.py
│   ├── enhanced_capture_all_formats.py
│   └── enhanced_packet_extractor.py
│
├── debug/                    # Debug and test scripts
│   ├── debug_desktop_app.py
│   ├── minimal_test.py
│   ├── simple_launcher.py
│   └── test_imports.py
│
├── tools/                    # Development tools
│   └── check_requirements.py # Requirements checker
│
├── docs/                     # Documentation
│   ├── CSV_EXPORT_FIX_SUMMARY.md
│   ├── FLOW_ANALYSIS_README.md
│   ├── INDIVIDUAL_COLUMNS_FIX.md
│   ├── README_ML_WORKFLOW.md
│   ├── STOP_BUTTON_FIX.md
│   └── USAGE.md
│
├── examples/                 # Example files
│   └── test4949.pcap
│
├── config/                   # Configuration files
│   └── config.yaml
│
├── scripts/                  # Database and setup scripts
│   ├── __init__.py
│   └── setup_database.py
│
├── .zencoder/                # Zencoder rules
│   └── rules/
│
├── .git/                     # Git repository
├── .gitignore               # Git ignore file
├── LICENSE                   # MIT License
├── README.md                 # Main project readme
├── requirements.txt          # Python dependencies
├── setup.py                  # Package setup
├── run_pyguard.py           # Clean main launcher
├── organize_structure.py     # Structure organizer (can be deleted after use)
└── PROJECT_STRUCTURE.md      # This file
```

## Key Benefits of New Structure

### 1. **Clear Separation of Concerns**
- **desktop_app/**: Main application
- **pyguard/**: Core library modules
- **tests/**: All test files
- **scripts/**: Utility and workflow scripts
- **debug/**: Debugging and testing tools
- **docs/**: Documentation and guides
- **examples/**: Sample files and data
- **config/**: Configuration files

### 2. **Easy Navigation**
- Related files are grouped together
- Clear naming conventions
- Logical hierarchy

### 3. **Maintainability**
- Easy to find specific functionality
- Clear dependencies between modules
- Simplified testing and debugging

### 4. **Professional Appearance**
- Industry-standard structure
- Easy for new developers to understand
- Clean root directory

## How to Use

### **Running the Desktop App**
```bash
# Main launcher (recommended)
python run_pyguard.py

# Direct run
python desktop_app/desktop_app.py
```

### **Running Tests**
```bash
# Run all tests
python -m pytest tests/

# Run specific test
python tests/test_csv_export.py
```

### **Running Scripts**
```bash
# Flow analysis
python scripts/run_flow_analysis.py

# Packet capture
python scripts/capture_traffic.py
```

### **Checking Requirements**
```bash
python tools/check_requirements.py
```

## Migration Notes

After running the organizer:
1. **Delete** `organize_structure.py` (no longer needed)
2. **Update** any hardcoded paths in your code
3. **Test** that all functionality still works
4. **Commit** the new structure to version control

## Future Development

- Add new modules to appropriate directories
- Keep tests close to the code they test
- Maintain clear separation between core and utility code
- Document any new directories or file types
