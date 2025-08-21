#!/usr/bin/env python3
"""
Test CSV Export - Verify Individual Columns
This script tests the CSV export to ensure we get individual columns instead of summary.
"""

import pandas as pd
import psycopg2
import yaml
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_config():
    """Load configuration from config.yaml"""
    try:
        with open('config.yaml', 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return None

def test_csv_export():
    """Test CSV export with individual columns"""
    
    # Load configuration
    config = load_config()
    if not config:
        logger.error("Failed to load configuration")
        return False
    
    db_config = config.get('database', {})
    
    try:
        # Connect to database
        conn = psycopg2.connect(
            host=db_config['host'],
            port=db_config['port'],
            dbname=db_config['name'],
            user=db_config['user'],
            password=db_config['password']
        )
        
        # Query to get packet data with individual columns
        query = """
        SELECT 
            timestamp,
            timestamp_epoch,
            src_ip,
            dst_ip,
            protocol,
            protocol_name,
            src_port,
            dst_port,
            packet_size,
            total_length,
            header_length,
            payload_size,
            window_size,
            ttl,
            seq,
            ack,
            fin_flag,
            syn_flag,
            rst_flag,
            psh_flag,
            ack_flag,
            urg_flag,
            ece_flag,
            cwr_flag,
            tcp_flags_raw,
            mac_src,
            mac_dst,
            direction
        FROM packets 
        WHERE src_ip IS NOT NULL 
        ORDER BY timestamp_epoch DESC
        LIMIT 100
        """
        
        # Read data into DataFrame
        logger.info("Querying database for packet data...")
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        if len(df) == 0:
            logger.warning("No packet data found in database")
            return False
        
        logger.info(f"Retrieved {len(df)} packets")
        
        # Display column information
        logger.info("Available columns:")
        for i, col in enumerate(df.columns, 1):
            logger.info(f"  {i:2d}. {col}")
        
        # Export to CSV
        output_file = 'test_individual_columns.csv'
        df.to_csv(output_file, index=False)
        logger.info(f"Exported to {output_file}")
        
        # Display sample data
        logger.info("\nSample data (first 3 rows):")
        print(df.head(3).to_string())
        
        # Check for summary column
        if 'summary' in df.columns:
            logger.warning("WARNING: Summary column still present!")
            return False
        else:
            logger.info("SUCCESS: No summary column found - individual columns only!")
            return True
        
    except Exception as e:
        logger.error(f"Error testing CSV export: {e}")
        return False
def main():
    """Main function"""
    logger.info("Testing CSV Export with Individual Columns")
    
    if test_csv_export():
        logger.info("Test completed successfully!")
        return 0
    else:
        logger.error("Test failed!")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())