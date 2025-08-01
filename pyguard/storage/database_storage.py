"""
Database storage module for packet metadata
"""

import os
import logging
import json
from datetime import datetime
import psycopg2
from psycopg2.extras import Json, execute_values
import sqlalchemy as sa
from sqlalchemy import (
    create_engine, MetaData, Table, Column, Integer, Float, String, 
    DateTime, Boolean, JSON, ForeignKey, Text, LargeBinary, Index
)
from sqlalchemy.dialects.postgresql import JSONB

logger = logging.getLogger(__name__)

class DatabaseStorage:
    """Store packet metadata in PostgreSQL database"""
    
    def __init__(self, config):
        """Initialize database storage with configuration"""
        self.config = config
        self.db_config = config.database
        self.batch_size = self.db_config["batch_size"]
        
        # Create database connection string
        self.connection_string = (
            f"postgresql://{self.db_config['user']}:{self.db_config['password']}@"
            f"{self.db_config['host']}:{self.db_config['port']}/{self.db_config['name']}"
        )
        
        # Initialize SQLAlchemy engine and connection
        self.engine = None
        self.connection = None
        self.metadata = MetaData()
        
        # Define tables
        self._define_tables()
    
    def _define_tables(self):
        """Define database tables"""
        # Packets table
        self.packets_table = Table(
            'packets', self.metadata,
            Column('id', Integer, primary_key=True),
            Column('timestamp', DateTime, index=True),
            Column('timestamp_epoch', Float, index=True),
            Column('capture_length', Integer),
            Column('packet_length', Integer),
            Column('mac_src', String(17), index=True),
            Column('mac_dst', String(17), index=True),
            Column('eth_type', Integer),
            Column('ip_version', Integer),
            Column('src_ip', String(45), index=True),
            Column('dst_ip', String(45), index=True),
            Column('protocol', Integer),
            Column('protocol_name', String(10), index=True),
            Column('src_port', Integer, index=True),
            Column('dst_port', Integer, index=True),
            Column('direction', String(10), index=True),
            Column('ttl', Integer),
            Column('header_length', Integer),
            Column('total_length', Integer),
            Column('id', Integer),
            Column('flags', Integer),
            Column('fragment_offset', Integer),
            Column('window_size', Integer),
            Column('tcp_flags_raw', Integer),
            Column('tcp_flags', JSON),
            Column('payload_size', Integer),
            Column('dns', JSONB),
            Column('http', JSONB),
            Column('icmp_type', Integer),
            Column('icmp_code', Integer),
            Column('arp_op', Integer),
            Column('arp_op_name', String(20)),
            Column('raw_metadata', JSONB),
            
            # Create indexes for common query patterns
            Index('idx_packets_timestamp', 'timestamp'),
            Index('idx_packets_src_ip', 'src_ip'),
            Index('idx_packets_dst_ip', 'dst_ip'),
            Index('idx_packets_protocol_name', 'protocol_name'),
            Index('idx_packets_src_port', 'src_port'),
            Index('idx_packets_dst_port', 'dst_port'),
            Index('idx_packets_direction', 'direction'),
        )
        
        # Flow table for aggregated connection data
        self.flows_table = Table(
            'flows', self.metadata,
            Column('id', Integer, primary_key=True),
            Column('start_time', DateTime, index=True),
            Column('end_time', DateTime, index=True),
            Column('duration', Float),
            Column('src_ip', String(45), index=True),
            Column('dst_ip', String(45), index=True),
            Column('src_port', Integer, index=True),
            Column('dst_port', Integer, index=True),
            Column('protocol', Integer),
            Column('protocol_name', String(10), index=True),
            Column('packet_count', Integer),
            Column('byte_count', Integer),
            Column('direction', String(10), index=True),
            Column('metadata', JSONB),
            
            # Create indexes for common query patterns
            Index('idx_flows_start_time', 'start_time'),
            Index('idx_flows_src_ip', 'src_ip'),
            Index('idx_flows_dst_ip', 'dst_ip'),
            Index('idx_flows_protocol_name', 'protocol_name'),
            Index('idx_flows_src_port', 'src_port'),
            Index('idx_flows_dst_port', 'dst_port'),
            Index('idx_flows_direction', 'direction'),
        )
    
    def connect(self):
        """Connect to the database"""
        try:
            logger.info(f"Connecting to database at {self.db_config['host']}:{self.db_config['port']}")
            self.engine = create_engine(self.connection_string)
            self.connection = self.engine.connect()
            logger.info("Connected to database")
            return True
        except Exception as e:
            logger.error(f"Error connecting to database: {e}")
            return False
    
    def initialize_schema(self):
        """Initialize database schema"""
        try:
            logger.info("Initializing database schema")
            self.metadata.create_all(self.engine)
            logger.info("Database schema initialized")
            return True
        except Exception as e:
            logger.error(f"Error initializing database schema: {e}")
            return False
    
    def store_batch(self, batch_items):
        """Store a batch of packet metadata in the database"""
        if not self.connection:
            logger.error("Database connection not established")
            return False
        
        try:
            # Prepare data for insertion
            packet_rows = []
            
            for metadata in batch_items:
                # Extract common fields for packets table
                packet_row = {
                    'timestamp': datetime.fromisoformat(metadata['timestamp']) if isinstance(metadata['timestamp'], str) else metadata['timestamp'],
                    'timestamp_epoch': metadata.get('timestamp_epoch'),
                    'capture_length': metadata.get('capture_length'),
                    'packet_length': metadata.get('packet_length'),
                    'mac_src': metadata.get('mac_src'),
                    'mac_dst': metadata.get('mac_dst'),
                    'eth_type': metadata.get('eth_type'),
                    'ip_version': metadata.get('ip_version'),
                    'src_ip': metadata.get('src_ip'),
                    'dst_ip': metadata.get('dst_ip'),
                    'protocol': metadata.get('protocol'),
                    'protocol_name': metadata.get('protocol_name'),
                    'src_port': metadata.get('src_port'),
                    'dst_port': metadata.get('dst_port'),
                    'direction': metadata.get('direction'),
                    'ttl': metadata.get('ttl'),
                    'header_length': metadata.get('header_length'),
                    'total_length': metadata.get('total_length'),
                    'flags': metadata.get('flags'),
                    'fragment_offset': metadata.get('fragment_offset'),
                    'window_size': metadata.get('window_size'),
                    'tcp_flags_raw': metadata.get('tcp_flags_raw'),
                    'tcp_flags': metadata.get('tcp_flags'),
                    'payload_size': metadata.get('payload_size'),
                    'dns': metadata.get('dns'),
                    'http': metadata.get('http'),
                    'icmp_type': metadata.get('icmp_type'),
                    'icmp_code': metadata.get('icmp_code'),
                    'arp_op': metadata.get('arp_op'),
                    'arp_op_name': metadata.get('arp_op_name'),
                    'raw_metadata': metadata  # Store the full metadata as JSON
                }
                
                packet_rows.append(packet_row)
            
            # Insert packet data
            if packet_rows:
                with self.connection.begin():
                    self.connection.execute(self.packets_table.insert(), packet_rows)
            
            return True
        
        except Exception as e:
            logger.error(f"Error storing batch in database: {e}")
            return False
    
    def commit(self):
        """Commit pending transactions"""
        try:
            # SQLAlchemy handles transactions automatically
            logger.debug("Database commit called")
            return True
        except Exception as e:
            logger.error(f"Error committing database transaction: {e}")
            return False
    
    def close(self):
        """Close database connection"""
        try:
            if self.connection:
                self.connection.close()
                self.connection = None
            
            if self.engine:
                self.engine.dispose()
                self.engine = None
            
            logger.info("Database connection closed")
            return True
        except Exception as e:
            logger.error(f"Error closing database connection: {e}")
            return False