"""
Database manager for PyGuard Desktop application.
Handles storing and retrieving packet data from PostgreSQL database.
"""

import psycopg2
import psycopg2.extras
import uuid
import logging
import time
from datetime import datetime
import json

logger = logging.getLogger('desktop_app')

class DatabaseManager:
    """Manages database operations for packet storage and retrieval"""
    
    def __init__(self, config):
        """Initialize database manager with configuration"""
        self.config = config
        self.db_config = config.get('database', {})
        self.enabled = self.db_config.get('enabled', False)
        self.connection = None
        self.cursor = None
        self.batch_size = self.db_config.get('batch_size', 1000)
        self.commit_interval = self.db_config.get('commit_interval', 5)
        self.packet_buffer = []
        self.last_commit_time = time.time()
        self.capture_session = str(uuid.uuid4())
        
        # Initialize database if enabled
        if self.enabled:
            self.initialize_database()
    
    def initialize_database(self):
        """Initialize database connection and tables"""
        try:
            # Connect to database
            self.connection = psycopg2.connect(
                host=self.db_config.get('host', 'localhost'),
                port=self.db_config.get('port', 5432),
                dbname=self.db_config.get('name', 'pyguard_db'),
                user=self.db_config.get('user', 'postgres'),
                password=self.db_config.get('password', '')
            )
            
            # Create cursor
            self.cursor = self.connection.cursor(cursor_factory=psycopg2.extras.DictCursor)
            
            # Create tables if they don't exist
            self.create_tables()
            
            logger.info("Database connection established")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            self.enabled = False
            return False
    
    def create_tables(self):
        """Create necessary tables if they don't exist"""
        try:
            # First, check if the table exists
            self.cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = 'packets'
                );
            """)
            table_exists = self.cursor.fetchone()[0]
            
            if table_exists:
                # Check if capture_session column exists
                self.cursor.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.columns 
                        WHERE table_schema = 'public' 
                        AND table_name = 'packets' 
                        AND column_name = 'capture_session'
                    );
                """)
                column_exists = self.cursor.fetchone()[0]
                
                if not column_exists:
                    # Add capture_session column
                    logger.info("Adding capture_session column to packets table")
                    self.cursor.execute("""
                        ALTER TABLE packets 
                        ADD COLUMN capture_session VARCHAR(50);
                    """)
            else:
                # Create packets table
                logger.info("Creating packets table")
                self.cursor.execute("""
                    CREATE TABLE packets (
                        id SERIAL PRIMARY KEY,
                        frame_number INTEGER,
                        timestamp TIMESTAMP WITH TIME ZONE,
                        src_ip VARCHAR(45),
                        src_port INTEGER,
                        dst_ip VARCHAR(45),
                        dst_port INTEGER,
                        protocol VARCHAR(20),
                        size INTEGER,
                        summary TEXT,
                        layers JSONB,
                        raw_data BYTEA,
                        capture_session VARCHAR(50),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                    );
                """)
            
            # Create indexes if they don't exist
            logger.info("Creating indexes if they don't exist")
            self.cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
                CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);
                CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip);
                CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip);
                CREATE INDEX IF NOT EXISTS idx_packets_capture_session ON packets(capture_session);
            """)
            
            self.connection.commit()
            logger.info("Database tables and indexes created successfully")
            
        except Exception as e:
            logger.error(f"Error creating tables: {e}")
            raise
    
    def queue_packet(self, packet):
        """Add packet to database queue"""
        if not self.enabled:
            logger.debug("Database not enabled, skipping packet")
            return False
        
        if not self.connection:
            logger.warning("No database connection, attempting to reconnect")
            self.reconnect()
            if not self.connection:
                return False
        
        try:
            # Add packet to buffer
            self.packet_buffer.append(packet)
            
            # Log buffer size periodically
            if len(self.packet_buffer) % 100 == 0:
                logger.debug(f"Database buffer size: {len(self.packet_buffer)}")
            
            # Check if we need to commit
            current_time = time.time()
            if (len(self.packet_buffer) >= self.batch_size or 
                (current_time - self.last_commit_time) >= self.commit_interval):
                logger.info(f"Committing {len(self.packet_buffer)} packets to database (buffer full or interval reached)")
                self.commit_packets()
            
            return True
            
        except Exception as e:
            logger.error(f"Error queuing packet: {e}")
            return False
    
    def commit_packets(self):
        """Commit buffered packets to database"""
        if not self.enabled:
            logger.debug("Database not enabled, skipping commit")
            return False
            
        if not self.connection:
            logger.warning("No database connection, attempting to reconnect")
            self.reconnect()
            if not self.connection:
                return False
                
        if not self.packet_buffer:
            logger.debug("No packets to commit")
            return False
        
        start_time = time.time()
        try:
            # Log start of commit
            packet_count = len(self.packet_buffer)
            logger.info(f"Starting commit of {packet_count} packets to database")
            
            # Prepare data for batch insert
            packet_data = []
            for packet in self.packet_buffer:
                # Convert timestamp string to datetime if needed
                timestamp = packet.get('timestamp')
                if isinstance(timestamp, str):
                    try:
                        timestamp = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f')
                    except:
                        timestamp = datetime.now()
                
                # Convert layers to JSON
                layers = json.dumps(packet.get('layers', []))
                
                # Add packet data
                packet_data.append((
                    packet.get('frame_number'),
                    timestamp,
                    packet.get('src_ip', ''),
                    packet.get('src_port'),
                    packet.get('dst_ip', ''),
                    packet.get('dst_port'),
                    packet.get('protocol', ''),
                    packet.get('size', 0),
                    packet.get('summary', ''),
                    layers,
                    packet.get('raw_data', b''),
                    self.capture_session
                ))
            
            # Execute batch insert
            psycopg2.extras.execute_values(
                self.cursor,
                """
                INSERT INTO packets (
                    frame_number, timestamp, src_ip, src_port, dst_ip, dst_port,
                    protocol, size, summary, layers, raw_data, capture_session
                ) VALUES %s
                """,
                packet_data
            )
            
            # Commit transaction
            self.connection.commit()
            
            # Clear buffer and update last commit time
            self.packet_buffer = []
            self.last_commit_time = time.time()
            
            # Log successful commit with timing information
            elapsed_time = time.time() - start_time
            logger.info(f"Successfully committed {packet_count} packets to database in {elapsed_time:.2f} seconds")
            return True
            
        except Exception as e:
            logger.error(f"Error committing packets: {e}")
            # Try to reconnect
            logger.info("Attempting to reconnect to database after commit error")
            self.reconnect()
            return False
    
    def reconnect(self):
        """Attempt to reconnect to the database"""
        try:
            logger.info("Attempting to reconnect to database")
            
            # Close existing connection if it exists
            if self.connection:
                try:
                    self.connection.close()
                    logger.info("Closed existing database connection")
                except Exception as e:
                    logger.warning(f"Error closing existing database connection: {e}")
            
            # Connect to database
            self.connection = psycopg2.connect(
                host=self.db_config.get('host', 'localhost'),
                port=self.db_config.get('port', 5432),
                dbname=self.db_config.get('name', 'pyguard_db'),
                user=self.db_config.get('user', 'postgres'),
                password=self.db_config.get('password', '')
            )
            
            # Create cursor
            self.cursor = self.connection.cursor(cursor_factory=psycopg2.extras.DictCursor)
            
            logger.info("Successfully reconnected to database")
            return True
            
        except Exception as e:
            logger.error(f"Error reconnecting to database: {e}")
            self.connection = None
            self.cursor = None
            return False
    
    def get_packets(self, filters=None, limit=1000, offset=0, order_by='timestamp', order='DESC'):
        """Retrieve packets from database with filtering and pagination"""
        if not self.enabled or not self.connection:
            return []
        
        try:
            # Build query
            query = "SELECT * FROM packets"
            params = []
            
            # Add filters if provided
            if filters:
                where_clauses = []
                
                if 'protocol' in filters and filters['protocol']:
                    where_clauses.append("protocol = %s")
                    params.append(filters['protocol'])
                
                if 'src_ip' in filters and filters['src_ip']:
                    where_clauses.append("src_ip = %s")
                    params.append(filters['src_ip'])
                
                if 'dst_ip' in filters and filters['dst_ip']:
                    where_clauses.append("dst_ip = %s")
                    params.append(filters['dst_ip'])
                
                if 'start_time' in filters and filters['start_time']:
                    where_clauses.append("timestamp >= %s")
                    params.append(filters['start_time'])
                
                if 'end_time' in filters and filters['end_time']:
                    where_clauses.append("timestamp <= %s")
                    params.append(filters['end_time'])
                
                if 'capture_session' in filters and filters['capture_session']:
                    where_clauses.append("capture_session = %s")
                    params.append(filters['capture_session'])
                
                if where_clauses:
                    query += " WHERE " + " AND ".join(where_clauses)
            
            # Add order by
            query += f" ORDER BY {order_by} {order}"
            
            # Add limit and offset
            query += " LIMIT %s OFFSET %s"
            params.extend([limit, offset])
            
            # Execute query
            self.cursor.execute(query, params)
            
            # Fetch results
            rows = self.cursor.fetchall()
            
            # Convert to packet dictionaries
            packets = []
            for row in rows:
                packet = dict(row)
                
                # Convert JSONB to list
                if 'layers' in packet and packet['layers']:
                    try:
                        packet['layers'] = json.loads(packet['layers'])
                    except:
                        packet['layers'] = []
                
                packets.append(packet)
            
            return packets
            
        except Exception as e:
            logger.error(f"Error retrieving packets: {e}")
            self.reconnect()
            return []
    
    def get_packet_count(self, filters=None):
        """Get count of packets matching filters"""
        if not self.enabled or not self.connection:
            return 0
        
        try:
            # Build query
            query = "SELECT COUNT(*) FROM packets"
            params = []
            
            # Add filters if provided
            if filters:
                where_clauses = []
                
                if 'protocol' in filters and filters['protocol']:
                    where_clauses.append("protocol = %s")
                    params.append(filters['protocol'])
                
                if 'src_ip' in filters and filters['src_ip']:
                    where_clauses.append("src_ip = %s")
                    params.append(filters['src_ip'])
                
                if 'dst_ip' in filters and filters['dst_ip']:
                    where_clauses.append("dst_ip = %s")
                    params.append(filters['dst_ip'])
                
                if 'start_time' in filters and filters['start_time']:
                    where_clauses.append("timestamp >= %s")
                    params.append(filters['start_time'])
                
                if 'end_time' in filters and filters['end_time']:
                    where_clauses.append("timestamp <= %s")
                    params.append(filters['end_time'])
                
                if 'capture_session' in filters and filters['capture_session']:
                    where_clauses.append("capture_session = %s")
                    params.append(filters['capture_session'])
                
                if where_clauses:
                    query += " WHERE " + " AND ".join(where_clauses)
            
            # Execute query
            self.cursor.execute(query, params)
            
            # Fetch result
            count = self.cursor.fetchone()[0]
            
            return count
            
        except Exception as e:
            logger.error(f"Error getting packet count: {e}")
            self.reconnect()
            return 0
    
    def clear_packets(self, capture_session=None):
        """Clear packets from database"""
        if not self.enabled or not self.connection:
            return False
        
        try:
            if capture_session:
                # Clear packets for specific capture session
                self.cursor.execute("DELETE FROM packets WHERE capture_session = %s", (capture_session,))
            else:
                # Clear all packets
                self.cursor.execute("DELETE FROM packets")
            
            # Commit transaction
            self.connection.commit()
            
            logger.info(f"Cleared packets from database")
            return True
            
        except Exception as e:
            logger.error(f"Error clearing packets: {e}")
            self.reconnect()
            return False
    
    def ensure_commit(self):
        """Ensure packets are committed to database"""
        if self.packet_buffer:
            self.commit_packets()
    
    def close(self):
        """Close database connection"""
        try:
            # Commit any remaining packets
            if self.packet_buffer:
                self.commit_packets()
            
            # Close cursor and connection
            if self.cursor:
                self.cursor.close()
            
            if self.connection:
                self.connection.close()
            
            logger.info("Database connection closed")
            
        except Exception as e:
            logger.error(f"Error closing database connection: {e}")