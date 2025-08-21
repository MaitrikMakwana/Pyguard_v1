# PyGuard Usage Guide

This document provides instructions for using the PyGuard network traffic analyzer with PostgreSQL database integration.

## Overview

PyGuard is a powerful network traffic analysis tool that captures, processes, and stores detailed network traffic metadata. The scripts in this repository extend PyGuard's functionality to:

1. Capture network packets in real-time
2. Process and extract metadata from packets
3. Generate flow records from packet data
4. Store all data in a PostgreSQL database
5. Provide a real-time dashboard for traffic statistics

## Prerequisites

- Python 3.8 or higher
- PostgreSQL database
- Required Python packages:
  - scapy
  - psycopg2
  - pyyaml

## Setup

1. **Configure PostgreSQL Database**

   Update the `config.yaml` file with your PostgreSQL database credentials:

   ```yaml
   database:
     enabled: true
     type: postgresql
     host: localhost
     port: 5432
     name: pyguard_db
     user: postgres
     password: your_password
     batch_size: 1000
     commit_interval: 5  # seconds
   ```

2. **Create Database and Tables**

   Run the following scripts to create the database and tables:

   ```bash
   python create_db.py
   python create_tables.py
   ```

## Available Scripts

### 1. Database Setup

- **create_db.py**: Creates the PostgreSQL database
- **create_tables.py**: Creates the necessary tables in the database

### 2. Traffic Capture and Analysis

- **capture_traffic.py**: Captures network packets and stores them in the database
- **generate_flows.py**: Analyzes packet data and generates flow records
- **dashboard.py**: Displays real-time statistics about captured traffic
- **run_pyguard.py**: Runs all components together

### 3. Testing and Verification

- **check_database.py**: Verifies the database connection and structure
- **insert_test_data.py**: Inserts test data into the database
- **query_data.py**: Queries and displays data from the database

## Usage

### Running the Complete System

To run all components together:

```bash
python run_pyguard.py
```

This will:
- Start capturing packets from the selected network interface
- Generate flow records from the captured packets
- Display a real-time dashboard with traffic statistics

Press `Ctrl+C` to stop the application.

### Running Individual Components

You can also run each component separately:

1. **Capture Traffic**

   ```bash
   python capture_traffic.py
   ```

   This script captures network packets from the selected interface and stores them in the database.

2. **Generate Flows**

   ```bash
   python generate_flows.py
   ```

   This script analyzes packet data and generates flow records.

3. **View Dashboard**

   ```bash
   python dashboard.py
   ```

   This script displays real-time statistics about captured traffic.

## Database Schema

### Packets Table

The `packets` table stores individual packet information:

| Column | Type | Description |
|--------|------|-------------|
| id | SERIAL | Primary key |
| timestamp | TIMESTAMP | Packet capture time |
| timestamp_epoch | DOUBLE PRECISION | Timestamp in epoch format |
| capture_length | INTEGER | Captured packet length |
| packet_length | INTEGER | Original packet length |
| mac_src | VARCHAR | Source MAC address |
| mac_dst | VARCHAR | Destination MAC address |
| eth_type | INTEGER | Ethernet type |
| ip_version | INTEGER | IP version (4 or 6) |
| src_ip | VARCHAR | Source IP address |
| dst_ip | VARCHAR | Destination IP address |
| protocol | INTEGER | IP protocol number |
| protocol_name | VARCHAR | Protocol name (TCP, UDP, ICMP, etc.) |
| src_port | INTEGER | Source port |
| dst_port | INTEGER | Destination port |
| direction | VARCHAR | Packet direction (incoming or outgoing) |
| ttl | INTEGER | Time to live |
| header_length | INTEGER | IP header length |
| total_length | INTEGER | Total packet length |
| pkt_id | INTEGER | Packet ID |
| flags | INTEGER | IP flags |
| fragment_offset | INTEGER | Fragment offset |
| window_size | INTEGER | TCP window size |
| tcp_flags_raw | INTEGER | Raw TCP flags |
| tcp_flags | JSON | TCP flags as JSON array |
| payload_size | INTEGER | Payload size |
| dns | JSONB | DNS data |
| http | JSONB | HTTP data |
| icmp_type | INTEGER | ICMP type |
| icmp_code | INTEGER | ICMP code |
| arp_op | INTEGER | ARP operation |
| arp_op_name | VARCHAR | ARP operation name |
| raw_metadata | JSONB | Additional metadata |

### Flows Table

The `flows` table stores aggregated flow information:

| Column | Type | Description |
|--------|------|-------------|
| id | SERIAL | Primary key |
| start_time | TIMESTAMP | Flow start time |
| end_time | TIMESTAMP | Flow end time |
| duration | DOUBLE PRECISION | Flow duration in seconds |
| src_ip | VARCHAR | Source IP address |
| dst_ip | VARCHAR | Destination IP address |
| src_port | INTEGER | Source port |
| dst_port | INTEGER | Destination port |
| protocol | INTEGER | IP protocol number |
| protocol_name | VARCHAR | Protocol name (TCP, UDP, etc.) |
| packet_count | INTEGER | Number of packets in the flow |
| byte_count | INTEGER | Total bytes in the flow |
| direction | VARCHAR | Flow direction (incoming or outgoing) |
| metadata | JSONB | Additional flow metadata |

## Querying the Database with pgAdmin

You can use pgAdmin to query the database and analyze the captured data. Here are some example queries:

### View Recent Packets

```sql
SELECT id, timestamp, src_ip, dst_ip, protocol_name, src_port, dst_port
FROM packets
ORDER BY timestamp DESC
LIMIT 20;
```

### Count Packets by Protocol

```sql
SELECT protocol_name, COUNT(*) as count
FROM packets
GROUP BY protocol_name
ORDER BY count DESC;
```

### Find Top Source IP Addresses

```sql
SELECT src_ip, COUNT(*) as packet_count
FROM packets
GROUP BY src_ip
ORDER BY packet_count DESC
LIMIT 10;
```

### Find Top Destination Ports

```sql
SELECT dst_port, protocol_name, COUNT(*) as connection_count
FROM packets
WHERE dst_port IS NOT NULL
GROUP BY dst_port, protocol_name
ORDER BY connection_count DESC
LIMIT 10;
```

### View TCP Packets with Specific Flags

```sql
SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port, tcp_flags
FROM packets
WHERE protocol_name = 'TCP' AND tcp_flags @> '"SYN"'
ORDER BY timestamp DESC
LIMIT 10;
```

### Find Long-Duration Flows

```sql
SELECT id, start_time, end_time, duration, src_ip, dst_ip, protocol_name, packet_count, byte_count
FROM flows
ORDER BY duration DESC
LIMIT 10;
```

### Find High-Volume Flows

```sql
SELECT id, start_time, end_time, src_ip, dst_ip, protocol_name, packet_count, byte_count
FROM flows
ORDER BY byte_count DESC
LIMIT 10;
```

## Troubleshooting

### Database Connection Issues

If you encounter database connection issues:

1. Verify that PostgreSQL is running:
   ```bash
   # On Windows
   sc query postgresql
   
   # On Linux
   systemctl status postgresql
   ```

2. Check your database credentials in `config.yaml`

3. Ensure the database exists:
   ```bash
   python check_database.py
   ```

### Packet Capture Issues

If packet capture is not working:

1. Ensure you have the necessary permissions to capture packets

2. Check available network interfaces:
   ```bash
   python -c "from scapy.all import get_if_list; print(get_if_list())"
   ```

3. Update the `interface` setting in `config.yaml` with a valid interface name

### Performance Considerations

- For high-traffic networks, increase the `batch_size` in the database configuration
- Adjust the `flow_interval` to balance between real-time updates and system load
- Monitor system resource usage and adjust settings as needed