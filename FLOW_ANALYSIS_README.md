# PyGuard Flow-Based Analysis

This document explains how to use the enhanced PyGuard system to capture network traffic and convert it to flow-based format suitable for machine learning analysis and compatibility with datasets like CIC-IDS.

## Overview

The enhanced PyGuard system now includes:

1. **Enhanced Packet Capture** (`capture_traffic.py`) - Captures detailed packet information including all TCP flags, proper timestamps, and payload sizes
2. **Flow Analyzer** (`flow_analyzer.py`) - Converts packet-level data to flow-based features
3. **Pipeline Runner** (`run_flow_analysis.py`) - Automated pipeline for complete analysis

## New Features Added

### Enhanced Packet Fields

The packet capture now extracts these additional fields for ML compatibility:

- **Individual TCP Flags**: `fin_flag`, `syn_flag`, `rst_flag`, `psh_flag`, `ack_flag`, `urg_flag`, `ece_flag`, `cwr_flag`
- **Proper Timestamps**: Uses packet timestamps when available
- **Accurate Payload Size**: Calculates payload size correctly for TCP/UDP
- **Header Lengths**: Extracts TCP and UDP header lengths
- **Packet Size**: Total packet size for analysis

### Flow-Based Features

The flow analyzer generates 80+ features compatible with CIC-IDS format:

- **Basic Flow Info**: Flow ID, source/destination IPs and ports, protocol
- **Flow Statistics**: Duration, packet counts, byte counts
- **Packet Length Statistics**: Min, max, mean, std for forward/backward directions
- **Inter-Arrival Time (IAT)**: Flow, forward, and backward IAT statistics
- **TCP Flag Counts**: Counts of each TCP flag type
- **Flow Rates**: Bytes/second, packets/second
- **Window Sizes**: Initial window sizes for forward/backward directions
- **Payload Statistics**: Segment sizes and payload-related features

## Usage

### Method 1: Complete Pipeline (Recommended)

Run the complete analysis pipeline:

```bash
# Capture for 60 seconds and generate flow features
python run_flow_analysis.py

# Capture for 5 minutes
python run_flow_analysis.py --capture-duration 300

# Capture specific number of packets
python run_flow_analysis.py --packet-count 1000

# Skip capture and use existing data
python run_flow_analysis.py --skip-capture
```

### Method 2: Step-by-Step

#### Step 1: Capture Packets

```bash
# Normal packet capture
python capture_traffic.py

# The script will capture packets and store them in PostgreSQL database
```

#### Step 2: Export Packets to CSV

```bash
# Export all captured packets
python capture_traffic.py --export-csv

# Export to specific file
python capture_traffic.py --export-csv --output-file my_packets.csv
```

#### Step 3: Convert to Flow Format

```bash
# Convert all packets to flows
python flow_analyzer.py

# Convert recent data only (last 30 minutes)
python flow_analyzer.py --time-window 30

# Specify output file
python flow_analyzer.py --output-file my_flows.csv
```

## Output Files

### 1. captured_packets.csv

Packet-level data with fields:
- `timestamp`, `timestamp_epoch`
- `src_ip`, `dst_ip`, `src_port`, `dst_port`
- `protocol`, `protocol_name`
- `packet_size`, `total_length`, `header_length`, `payload_size`
- `fin_flag`, `syn_flag`, `rst_flag`, `psh_flag`, `ack_flag`, `urg_flag`, `ece_flag`, `cwr_flag`
- `window_size`, `ttl`
- Additional protocol-specific fields (HTTP, DNS, ICMP, ARP)

### 2. flow_features.csv

Flow-level data with 80+ features compatible with CIC-IDS:
- `Flow_ID`, `Src_IP`, `Dst_IP`, `Src_Port`, `Dst_Port`, `Protocol`
- `Flow_Duration`, `Tot_Fwd_Pkts`, `Tot_Bwd_Pkts`
- `TotLen_Fwd_Pkts`, `TotLen_Bwd_Pkts`
- `Fwd_Pkt_Len_Max`, `Fwd_Pkt_Len_Min`, `Fwd_Pkt_Len_Mean`, `Fwd_Pkt_Len_Std`
- `Bwd_Pkt_Len_Max`, `Bwd_Pkt_Len_Min`, `Bwd_Pkt_Len_Mean`, `Bwd_Pkt_Len_Std`
- `Flow_Byts/s`, `Flow_Pkts/s`
- `Flow_IAT_Mean`, `Flow_IAT_Std`, `Flow_IAT_Max`, `Flow_IAT_Min`
- `Fwd_IAT_Tot`, `Fwd_IAT_Mean`, `Fwd_IAT_Std`, `Fwd_IAT_Max`, `Fwd_IAT_Min`
- `Bwd_IAT_Tot`, `Bwd_IAT_Mean`, `Bwd_IAT_Std`, `Bwd_IAT_Max`, `Bwd_IAT_Min`
- TCP flag counts: `FIN_Flag_Cnt`, `SYN_Flag_Cnt`, `RST_Flag_Cnt`, etc.
- And many more...

## Machine Learning Usage

The generated `flow_features.csv` can be directly used for:

1. **Intrusion Detection**: Train models to classify network flows as benign or malicious
2. **Traffic Classification**: Classify flows by application or protocol
3. **Anomaly Detection**: Detect unusual network behavior
4. **Performance Analysis**: Analyze network performance characteristics

### Example ML Pipeline

```python
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# Load flow data
df = pd.read_csv('flow_features.csv')

# Prepare features (exclude non-numeric columns)
feature_cols = df.select_dtypes(include=[np.number]).columns.tolist()
feature_cols.remove('Label')  # Remove target column if present

X = df[feature_cols]
y = df['Label']  # Assuming you have labels

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train_scaled, y_train)

# Evaluate
accuracy = model.score(X_test_scaled, y_test)
print(f"Model accuracy: {accuracy:.2f}")
```

## Configuration

Make sure your `config.yaml` includes database configuration:

```yaml
database:
  host: localhost
  port: 5432
  name: pyguard
  user: your_username
  password: your_password

interface: eth0  # or your network interface
packet_count: 0  # 0 for unlimited, or specific number
```

## Requirements

All required packages are listed in `requirements.txt`:
- pandas>=1.5.0 (for data processing)
- psycopg2-binary>=2.9.5 (for PostgreSQL)
- scapy>=2.5.0 (for packet capture)
- PyYAML>=6.0 (for configuration)

## Troubleshooting

### Common Issues

1. **Permission Error**: Run with administrator/root privileges for packet capture
2. **Database Connection**: Ensure PostgreSQL is running and credentials are correct
3. **Network Interface**: Check available interfaces with `python -c "from scapy.arch import get_if_list; print(get_if_list())"`
4. **Empty Output**: Ensure there's network traffic during capture period

### Debugging

Enable debug logging by modifying the logging level:

```python
logging.basicConfig(level=logging.DEBUG)
```

## Performance Considerations

- **Memory Usage**: Large packet captures may consume significant memory
- **Processing Time**: Flow conversion time depends on number of packets and flows
- **Storage**: Consider database storage limits for long-term captures
- **Network Impact**: Packet capture may impact network performance on busy interfaces

## Next Steps

1. **Labeling**: Add labels to flows for supervised learning
2. **Feature Engineering**: Create additional domain-specific features
3. **Real-time Processing**: Implement streaming flow analysis
4. **Visualization**: Create dashboards for flow analysis results