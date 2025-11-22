"""
Entry point for PCAP Attack Detection Microservice
"""

try:
    from app.main import app
    from config.config import Config
except ImportError:
    from Final_IDS.app.main import app  # type: ignore
    from Final_IDS.config.config import Config  # type: ignore

if __name__ == '__main__':
    print("=" * 60)
    print("PCAP to Attack Detection Microservice")
    print("=" * 60)
    print(f"CICFlowMeter path: {Config.CICFLOWMETER_BIN}")
    print("\nEndpoints:")
    print("  GET  /health - Health check")
    print("  POST /analyze - Upload pcap file (multipart/form-data)")
    print("  POST /analyze_file - Provide pcap file path (JSON)")
    print(f"\nStarting server on http://{Config.HOST}:{Config.PORT}")
    print("=" * 60)
    
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)

