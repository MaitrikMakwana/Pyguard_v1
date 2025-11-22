# Network Attack Detection Microservice (IDS)

A production-ready microservice for Intrusion Detection Systems (IDS) that analyzes network packet captures (PCAP files) and detects various types of network attacks using a Graph Convolutional Network (GCN) model.

## 🎯 Purpose

This microservice is designed for IDS systems that:
1. **Capture network packets** as `.pcap` files
2. **Send PCAP files** to this service for analysis
3. **Receive attack detection results** with detailed classifications

## 🏗️ Architecture

```
Final_IDS/
├── app/                          # Application (MVC structure)
│   ├── main.py                   # Flask API endpoints
│   ├── models/
│   │   └── gcn_model.py         # GCN model & prediction logic
│   └── services/
│       ├── cicflowmeter_service.py      # PCAP → CSV conversion
│       ├── feature_alignment_service.py # Feature alignment & post-processing
│       └── prediction_service.py        # Attack prediction
├── config/                       # Configuration
│   └── config.py
├── Saved_Model/                  # Trained model files (required)
├── CICFlowmeter/                 # CICFlowMeter tool (required)
├── requirements.txt
├── run.py                        # Service entry point
└── README.md
```

## 📋 Prerequisites

- **Python 3.8+**
- **Java** (required for CICFlowMeter)
- **All dependencies** from `requirements.txt`

## 🚀 Installation

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 2. Verify Java Installation

```bash
java -version
```

Java must be installed and accessible in PATH.

### 3. Verify Required Files

Ensure all model files exist in `Saved_Model/`:
- `gcn_model_complete.pth`
- `gcn_model.pth`
- `scaler.pkl`
- `label_encoder.pkl`
- `model_metadata.pkl`

Ensure CICFlowMeter is in `CICFlowmeter/CICFlowMeter-4.0/bin/cfm.bat`

## 🎯 Usage for IDS System

### Start the Service

```bash
python run.py
```

The service starts on `http://localhost:5000` (configurable in `config/config.py`)

### Integration with IDS System

#### Option 1: Upload PCAP File (Recommended)

When your IDS captures a PCAP file, send it to the service:

```python
import requests

# Your IDS system captures packets and saves as pcap_file.pcap
pcap_file_path = "captured_packets.pcap"

# Send to attack detection service
with open(pcap_file_path, 'rb') as f:
    response = requests.post(
        'http://localhost:5000/analyze',
        files={'file': f}
    )

# Get attack detection results
results = response.json()

# Process results
if results['status'] == 'success':
    total_flows = results['total_flows']
    attack_flows = results['attack_flows']
    benign_flows = results['benign_flows']
    
    print(f"Analysis complete: {attack_flows} attacks detected out of {total_flows} flows")
    
    # Check specific attack types
    for attack in results['top_attacks']:
        if attack['attack_type'] != 'BENIGN':
            print(f"  {attack['attack_type']}: {attack['count']} flows ({attack['percentage']}%)")
```

#### Option 2: Provide File Path

If the PCAP file is already on the server:

```python
import requests

response = requests.post(
    'http://localhost:5000/analyze_file',
    json={'pcap_path': '/path/to/captured_packets.pcap'}
)

results = response.json()
```

### API Endpoints

#### 1. Health Check

```bash
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "service": "PCAP Attack Detection Service"
}
```

#### 2. Analyze PCAP File (Upload)

```bash
POST /analyze
Content-Type: multipart/form-data
```

**Request:**
- `file`: PCAP file (multipart/form-data)

**Response:**
```json
{
  "status": "success",
  "total_flows": 100,
  "attack_flows": 15,
  "benign_flows": 85,
  "average_confidence": 0.95,
  "attack_summary": {
    "BENIGN": 85,
    "DoS": 10,
    "DDoS": 5
  },
  "top_attacks": [
    {
      "attack_type": "DoS",
      "count": 10,
      "percentage": 10.0,
      "avg_confidence": 0.92
    }
  ],
  "detailed_results": [...]
}
```

#### 3. Analyze PCAP File (File Path)

```bash
POST /analyze_file
Content-Type: application/json
```

**Request Body:**
```json
{
  "pcap_path": "/path/to/file.pcap"
}
```

## 🔄 Processing Pipeline

The service automatically:

1. **Receives PCAP file** from your IDS system
2. **Converts to CSV** using CICFlowMeter (extracts network flow features)
3. **Aligns features** to match model schema (renames columns, applies post-processing)
4. **Preprocesses data** (scaling, normalization)
5. **Creates graph structure** (k-NN graph from flow features)
6. **Runs GCN model** for attack classification
7. **Returns results** with attack types and confidence scores

## 📊 Attack Types Detected

- **BENIGN**: Normal network traffic
- **DoS**: Denial of Service attacks
- **DDoS**: Distributed Denial of Service attacks
- **PortScan**: Port scanning attempts
- **Other**: Other types of attacks

## ⚙️ Configuration

Edit `config/config.py` to modify:

- **HOST**: Server host (default: `0.0.0.0`)
- **PORT**: Server port (default: `5000`)
- **DEBUG**: Debug mode (default: `False`)
- **MAX_CONTENT_LENGTH**: Max file upload size (default: 500MB)

Or set environment variables:
```bash
export HOST=0.0.0.0
export PORT=5000
export DEBUG=False
```

## 🔧 Integration Example

### Complete IDS Integration Workflow

```python
import requests
import time
from pathlib import Path

class IDSAttackDetector:
    def __init__(self, service_url="http://localhost:5000"):
        self.service_url = service_url
    
    def check_service_health(self):
        """Check if service is running"""
        try:
            response = requests.get(f"{self.service_url}/health", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def analyze_captured_packets(self, pcap_file_path):
        """
        Analyze captured PCAP file for attacks
        
        Args:
            pcap_file_path: Path to captured PCAP file
            
        Returns:
            Dictionary with attack detection results
        """
        if not Path(pcap_file_path).exists():
            return {"error": "PCAP file not found"}
        
        try:
            with open(pcap_file_path, 'rb') as f:
                response = requests.post(
                    f"{self.service_url}/analyze",
                    files={'file': f},
                    timeout=300  # 5 minutes for large files
                )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"Service error: {response.status_code}", "details": response.text}
        
        except Exception as e:
            return {"error": str(e)}
    
    def get_attack_summary(self, results):
        """Extract attack summary from results"""
        if results.get('status') != 'success':
            return None
        
        summary = {
            'total_flows': results.get('total_flows', 0),
            'attack_flows': results.get('attack_flows', 0),
            'benign_flows': results.get('benign_flows', 0),
            'attacks': []
        }
        
        for attack in results.get('top_attacks', []):
            if attack['attack_type'] != 'BENIGN':
                summary['attacks'].append({
                    'type': attack['attack_type'],
                    'count': attack['count'],
                    'percentage': attack['percentage'],
                    'confidence': attack['avg_confidence']
                })
        
        return summary

# Usage in your IDS system
detector = IDSAttackDetector()

# Check service is running
if not detector.check_service_health():
    print("ERROR: Attack detection service is not running!")
    exit(1)

# Analyze captured packets
pcap_file = "captured_traffic.pcap"
results = detector.analyze_captured_packets(pcap_file)

if results.get('status') == 'success':
    summary = detector.get_attack_summary(results)
    print(f"Analysis complete:")
    print(f"  Total flows: {summary['total_flows']}")
    print(f"  Attack flows: {summary['attack_flows']}")
    print(f"  Benign flows: {summary['benign_flows']}")
    
    if summary['attacks']:
        print(f"\nDetected attacks:")
        for attack in summary['attacks']:
            print(f"  {attack['type']}: {attack['count']} flows ({attack['percentage']}%)")
    else:
        print("\nNo attacks detected - traffic is benign")
else:
    print(f"Error: {results.get('error')}")
```

## 🐛 Troubleshooting

### Service Not Responding
- Check if service is running: `python run.py`
- Verify port is not in use: Change PORT in `config/config.py`
- Check logs for errors

### CICFlowMeter Errors
- **Issue**: "CICFlowMeter failed" or "Java not found"
- **Solution**: 
  - Verify Java: `java -version`
  - Check CICFlowMeter path in `config/config.py`
  - Ensure `cfm.bat` exists in `CICFlowmeter/CICFlowMeter-4.0/bin/`

### Model Loading Errors
- **Issue**: "Required file not found"
- **Solution**: Verify all files exist in `Saved_Model/` directory

### Large File Processing
- **Issue**: Timeout errors for large PCAP files
- **Solution**: Increase timeout in your client code (default: 300 seconds)

## 📝 Response Format Details

### Success Response
```json
{
  "status": "success",
  "total_flows": 100,
  "attack_flows": 15,
  "benign_flows": 85,
  "average_confidence": 0.95,
  "attack_summary": {
    "BENIGN": 85,
    "DoS": 10,
    "DDoS": 5
  },
  "top_attacks": [
    {
      "attack_type": "DoS",
      "count": 10,
      "percentage": 10.0,
      "avg_confidence": 0.92
    }
  ],
  "detailed_results": [
    {
      "Predicted_Label": "DoS",
      "Confidence": 0.95,
      "Prob_BENIGN": 0.02,
      "Prob_DoS": 0.95,
      "Prob_DDoS": 0.01,
      ...
    }
  ]
}
```

### Error Response
```json
{
  "status": "error",
  "error": "Error message",
  "traceback": "..."
}
```

## 🔒 Security Notes

- Service accepts file uploads up to 500MB (configurable)
- Temporary files are automatically cleaned up
- No persistent storage of uploaded files
- Consider adding authentication for production use
- Run behind a reverse proxy (nginx) for production

## 📞 Support

For issues:
1. Check troubleshooting section
2. Verify all requirements are met
3. Check service logs for detailed error messages
4. Ensure model files are not corrupted

## 📄 License

See individual component licenses:
- CICFlowMeter: See `CICFlowmeter/CICFlowMeter-4.0/LICENSE.txt`
- Model: Check with model provider
