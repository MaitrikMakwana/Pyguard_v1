#!/usr/bin/env python3
"""
Database setup script for PyGuard

This script creates the necessary database schema for PyGuard.
It can be run directly or imported and used programmatically.
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# Add parent directory to path to allow importing pyguard
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pyguard.core.config import Config
from pyguard.storage.database_storage import DatabaseStorage

def setup_logging(verbose=False):
    """Set up logging"""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='PyGuard Database Setup')
    parser.add_argument('-c', '--config', type=str, default='config.yaml',
                        help='Path to configuration file')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose logging')
    parser.add_argument('--host', type=str,
                        help='Database host')
    parser.add_argument('--port', type=int,
                        help='Database port')
    parser.add_argument('--name', type=str,
                        help='Database name')
    parser.add_argument('--user', type=str,
                        help='Database user')
    parser.add_argument('--password', type=str,
                        help='Database password')
    parser.add_argument('--drop', action='store_true',
                        help='Drop existing tables before creating new ones')
    
    return parser.parse_args()

def setup_database(config, drop_existing=False):
    """Set up the database schema"""
    logger = logging.getLogger(__name__)
    
    try:
        # Create database storage instance
        db_storage = DatabaseStorage(config)
        
        # Connect to database
        if not db_storage.connect():
            logger.error("Failed to connect to database")
            return False
        
        # Drop existing tables if requested
        if drop_existing:
            logger.info("Dropping existing tables...")
            db_storage.metadata.drop_all(db_storage.engine)
            logger.info("Existing tables dropped")
        
        # Create tables
        logger.info("Creating database schema...")
        db_storage.initialize_schema()
        logger.info("Database schema created successfully")
        
        # Close connection
        db_storage.close()
        
        return True
    
    except Exception as e:
        logger.error(f"Error setting up database: {e}")
        return False

def main():
    """Main entry point"""
    # Parse command line arguments
    args = parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    # Load configuration
    config_path = Path(args.config)
    config = Config(config_path if config_path.exists() else None)
    
    # Override config with command line arguments
    if args.host:
        config.database["host"] = args.host
    if args.port:
        config.database["port"] = args.port
    if args.name:
        config.database["name"] = args.name
    if args.user:
        config.database["user"] = args.user
    if args.password:
        config.database["password"] = args.password
    
    # Print database connection info
    logger.info(f"Setting up database: {config.database['host']}:{config.database['port']}/{config.database['name']}")
    
    # Setup database
    if setup_database(config, args.drop):
        logger.info("Database setup completed successfully")
        return 0
    else:
        logger.error("Database setup failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())