# PyGuard ML Workflow - Complete Guide

This guide explains how to use PyGuard's machine learning workflow to convert network traffic data into flow-based features compatible with CIC-IDS dataset format for ML analysis.

## 🚀 Quick Start

### Option 1: Convert PCAP File to Flow Features
```bash
# Convert existing PCAP file to ML-ready flow features
python pcap_to_flows.py your_traffic.pcap -o flow_features.csv

# Run demo with sample PCAP
python demo_complete_workflow.py pcap --pcap-file your_traffic.pcap
```

### Option 2: Live Capture to Flow Features
```bash
# Capture live traffic and convert to flows
python demo_complete_workflow.py live --duration 60 --count 5000

# Or capture directly to CSV first
python capture_to_csv.py -o packets.csv -c 1000
python ml_flow_converter.py --source csv --input-file packets.csv
```

### Option 3: Database to Flow Features
```bash
# Convert existing database packets to flows
python demo_complete_workflow.py database

# Or use the ML converter directly
python ml_flow_converter.py --source database --output-file flows.csv
```

## 📁 New Files Overview

### Core Scripts

1. **`pcap_to_flows.py`** - Main PCAP to flow converter
   - Reads .pcap files using Scapy
   - Groups packets into flows
   - Calculates comprehensive flow statistics
   - Exports CIC-IDS compatible CSV

2. **`capture_to_csv.py`** - Live packet capture to CSV
   - Captures packets with all essential fields
   - Saves directly to CSV format
   - Includes application protocol detection

3. **`ml_flow_converter.py`** - Advanced flow converter
   - Works with database or CSV input
   - Comprehensive flow feature calculation
   - CIC-IDS dataset compatibility

4. **`enhanced_packet_extractor.py`** - Enhanced packet extraction
   - Comprehensive packet information extraction
   - All essential fields for ML analysis

5. **`complete_ml_pipeline.py`** - Complete pipeline orchestrator
   - End-to-end workflow management
   - Multiple input/output options

6. **`demo_complete_workflow.py`** - Interactive demo script
   - Shows complete workflow examples
   - Easy testing and validation

## 🔧 Installation & Setup

### Prerequisites
```bash
# Install required packages
pip install scapy pandas numpy psycopg2-binary pyyaml

# On Windows, install Npcap for packet capture
# Download from: https://npcap.com/
```

### Configuration
Make sure your `config.yaml` is properly configured:
```yaml
database:
  enabled: true
  host: localhost
  port: 5432
  name: pyguard_db
  user: postgres
  password: your_password
```

## 📊 Essential Fields Extracted

### Packet-Level Fields
```python
packet_info = {
    # Network Layer
    'src_ip': packet[IP].src,
    'dst_ip': packet[IP].dst,
    'protocol': packet[IP].proto,  # TCP=6, UDP=17, ICMP=1
    'total_length': packet[IP].len,
    'ttl': packet[IP].ttl,
    
    # Transport Layer
    'src_port': packet[TCP/UDP].sport,
    'dst_port': packet[TCP/UDP].dport,
    'packet_size': len(packet),
    'header_length': packet[TCP].dataofs * 4,  # TCP only
    
    # TCP Flags
    'fin_flag': packet[TCP].flags.F,
    'syn_flag': packet[TCP].flags.S,
    'rst_flag': packet[TCP].flags.R,
    'psh_flag': packet[TCP].flags.P,
    'ack_flag': packet[TCP].flags.A,
    'urg_flag': packet[TCP].flags.U,
    'ece_flag': packet[TCP].flags.E,
    'cwr_flag': packet[TCP].flags.C,
    
    # Timing & Payload
    'timestamp': packet.time,
    'window_size': packet[TCP].window,
    'payload_size': len(packet[TCP/UDP].payload)
}
```

### Flow-Level Features (CIC-IDS Compatible)
- **Flow identification**: Flow_ID, Src_IP, Dst_IP, Src_Port, Dst_Port, Protocol
- **Flow timing**: Flow_Duration, Flow_Start_Time, Flow_End_Time
- **Packet counts**: Tot_Fwd_Pkts, Tot_Bwd_Pkts
- **Byte counts**: TotLen_Fwd_Pkts, TotLen_Bwd_Pkts
- **Packet length stats**: Fwd_Pkt_Len_Min/Max/Mean/Std, Bwd_Pkt_Len_*
- **Inter-arrival times**: Flow_IAT_*, Fwd_IAT_*, Bwd_IAT_*
- **TCP flags**: FIN_Flag_Cnt, SYN_Flag_Cnt, RST_Flag_Cnt, etc.
- **Header lengths**: Fwd_Header_Len, Bwd_Header_Len
- **Flow rates**: Flow_Byts/s, Flow_Pkts/s
- **And 80+ more features for comprehensive ML analysis**

## 🎯 Usage Examples

### Example 1: Basic PCAP Conversion
```bash
# Convert PCAP to flows with all features
python pcap_to_flows.py traffic.pcap -o flows.csv --verbose

# Limit processing for large files
python pcap_to_flows.py large_traffic.pcap -o flows.csv --max-packets 100000
```

### Example 2: Live Traffic Capture
```bash
# Capture 1000 packets and save to CSV
python capture_to_csv.py -o live_packets.csv -c 1000

# Capture for 60 seconds with filter
python capture_to_csv.py -o web_traffic.csv -t 60 --filter "tcp port 80 or tcp port 443"

# Convert captured packets to flows
python ml_flow_converter.py --source csv --input-file live_packets.csv -o live_flows.csv
```

### Example 3: Database Integration
```bash
# First capture packets to database
python capture_traffic.py  # Let it run for a while

# Then convert database packets to flows
python ml_flow_converter.py --source database --output-file db_flows.csv --time-window 60
```

### Example 4: Complete Pipeline
```bash
# Run complete pipeline with live capture
python complete_ml_pipeline.py --capture-method csv --duration 120 --packet-count 5000

# Run pipeline with database
python complete_ml_pipeline.py --capture-method database --duration 60
```

## 📈 Output Format

### CSV Structure
The output CSV files contain flows with CIC-IDS compatible column names:

```csv
Flow_ID,Src_IP,Dst_IP,Src_Port,Dst_Port,Protocol,Flow_Duration,Tot_Fwd_Pkts,Tot_Bwd_Pkts,TotLen_Fwd_Pkts,TotLen_Bwd_Pkts,Fwd_Pkt_Len_Max,Fwd_Pkt_Len_Min,Fwd_Pkt_Len_Mean,Fwd_Pkt_Len_Std,Bwd_Pkt_Len_Max,Bwd_Pkt_Len_Min,Bwd_Pkt_Len_Mean,Bwd_Pkt_Len_Std,Flow_Byts/s,Flow_Pkts/s,Flow_IAT_Mean,Flow_IAT_Std,Flow_IAT_Max,Flow_IAT_Min,Fwd_IAT_Tot,Fwd_IAT_Mean,Fwd_IAT_Std,Fwd_IAT_Max,Fwd_IAT_Min,Bwd_IAT_Tot,Bwd_IAT_Mean,Bwd_IAT_Std,Bwd_IAT_Max,Bwd_IAT_Min,Fwd_PSH_Flags,Bwd_PSH_Flags,Fwd_URG_Flags,Bwd_URG_Flags,Fwd_Header_Len,Bwd_Header_Len,Fwd_Pkts/s,Bwd_Pkts/s,Pkt_Len_Min,Pkt_Len_Max,Pkt_Len_Mean,Pkt_Len_Std,Pkt_Len_Var,FIN_Flag_Cnt,SYN_Flag_Cnt,RST_Flag_Cnt,PSH_Flag_Cnt,ACK_Flag_Cnt,URG_Flag_Cnt,CWE_Flag_Count,ECE_Flag_Cnt,Init_Win_bytes_forward,Init_Win_bytes_backward,Fwd_Seg_Size_Min,Fwd_Seg_Size_Avg,Bwd_Seg_Size_Avg,Subflow_Fwd_Pkts,Subflow_Fwd_Byts,Subflow_Bwd_Pkts,Subflow_Bwd_Byts,Active_Mean,Active_Std,Active_Max,Active_Min,Idle_Mean,Idle_Std,Idle_Max,Idle_Min,Label
```

### Ready for ML Analysis
The output is directly compatible with:
- **Scikit-learn** for traditional ML algorithms
- **TensorFlow/PyTorch** for deep learning
- **CIC-IDS datasets** for comparison and benchmarking
- **Network security research** and anomaly detection

## 🔍 Validation & Testing

### Run Demos
```bash
# Show all available examples
python demo_complete_workflow.py examples

# Test with sample data
python demo_complete_workflow.py live --duration 30 --count 500
```

### Validate Output
```bash
# Check if all essential fields are present
python complete_ml_pipeline.py --validate --input-csv your_flows.csv
```

## 🚨 Troubleshooting

### Common Issues

1. **Permission Errors (Windows)**
   - Run as Administrator
   - Install Npcap with WinPcap compatibility

2. **No Packets Captured**
   - Check network interface: `python -c "from scapy.arch import get_if_list; print(get_if_list())"`
   - Try different interface: `--interface "Ethernet"`

3. **Database Connection Errors**
   - Verify PostgreSQL is running
   - Check config.yaml database settings
   - Ensure database exists: `python scripts/setup_database.py`

4. **Large PCAP Files**
   - Use `--max-packets` to limit processing
   - Process in chunks for very large files

### Performance Tips

- Use `--max-packets` for large PCAP files
- Enable `--verbose` for debugging
- Use SSD storage for better I/O performance
- Increase system memory for large datasets

## 📚 Integration with Existing PyGuard

These new scripts integrate seamlessly with your existing PyGuard setup:

1. **Database Integration**: Uses same PostgreSQL database and config
2. **UI Integration**: Can be called from desktop application
3. **Configuration**: Uses same `config.yaml` file
4. **Logging**: Consistent logging format and levels

## 🎓 Next Steps

1. **Capture your network traffic** using any method above
2. **Convert to flow features** using the provided scripts
3. **Load into your ML framework** (scikit-learn, TensorFlow, etc.)
4. **Train models** for network security, anomaly detection, or traffic classification
5. **Deploy models** for real-time network monitoring

## 📞 Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the demo scripts for examples
3. Examine the verbose output for debugging information

Your network traffic data is now ready for advanced machine learning analysis! 🚀