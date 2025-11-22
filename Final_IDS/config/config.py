"""
Configuration settings
"""

import os


class Config:
    """Application configuration"""
    
    # Flask settings
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB max file size
    
    # Paths
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    CICFLOWMETER_BIN = os.path.join(BASE_DIR, "CICFlowmeter", "CICFlowMeter-4.0", "bin", "cfm.bat")
    SAVED_MODEL_DIR = os.path.join(BASE_DIR, "Saved_Model")
    
    # API settings
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', 5000))
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'

