# PyGuard Desktop Application

A desktop application for network packet capture and advanced filtering with a minimal user interface.

## Features

- **Packet Capture**: Captures network packets from selected interfaces
- **Advanced Filtering**: Filter packets by protocol, IP, port, and more
- **Real-time Statistics**: Displays packet counts, rates, and protocol distribution
- **Packet Inspection**: View detailed packet information in real-time
- **Network Interface Selection**: Easy selection of network interfaces
- **Logging**: Integrated log viewer for monitoring application activity

## Requirements

- Python 3.8 or higher
- PyQt5 for the user interface

## Installation

1. Install PyQt5:
   ```bash
   pip install PyQt5
   ```

## Usage

1. Run the desktop application:
   ```bash
   python desktop_app/run_desktop_app.py
   ```

2. Select a network interface from the dropdown menu

3. Enter filter expressions (optional):
   - `tcp` - Capture only TCP packets
   - `udp` - Capture only UDP packets
   - `host 192.168.1.1` - Capture packets to/from a specific IP
   - `port 80` - Capture packets to/from a specific port
   - Combine filters: `tcp and port 443` - Capture HTTPS traffic

4. Click "Start Capture" to begin capturing network traffic

5. Monitor packet information and statistics in real-time

6. Click "Stop Capture" to stop the capture process

## Advanced Filtering

The application supports powerful filtering capabilities:
- **Protocol Filtering**: Filter by TCP, UDP, ICMP, or other protocols
- **IP Filtering**: Filter by source or destination IP address
- **Port Filtering**: Filter by source or destination port
- **Combination Filters**: Combine multiple filters for precise packet selection

## Troubleshooting

- If you encounter issues with network interface detection, use the "Enter manually" option
- Check the log viewer for detailed error messages and application status
- For performance issues, try using more specific filters to reduce the number of captured packets