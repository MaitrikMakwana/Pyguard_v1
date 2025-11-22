PyGuard IDS Integration Design
Architecture Overview
┌─────────────────────────────────────┐
│   Desktop App (PyQt5)               │
│  ┌─────────────────────────────────┐│
│  │ Toolbar                         ││
│  │ [Start] [Stop] [Save] [Analyze] ││◄─── NEW "Analyze with IDS" Button
│  └─────────────────────────────────┘│
│                                       │
│  ┌─────────────────────────────────┐│
│  │ Details Tabs                     ││
│  │ ├─ Packet Analysis              ││
│  │ ├─ Advanced Filter              ││
│  │ ├─ Database Status              ││
│  │ └─ IDS Analysis (NEW) ◄──────────│──── NEW TAB for Attack Results
│  └─────────────────────────────────┘│
│                                       │
└─────────────────────────────────────┘
            ↓
     HTTP POST Request
            ↓
┌─────────────────────────────────────┐
│  Final_IDS Flask Service            │
│  (Separate Process)                 │
│  http://localhost:5000              │
│                                       │
│  POST /analyze                       │
│  ├─ CICFlowMeter (PCAP→CSV)         │
│  ├─ Feature Alignment               │
│  └─ GCN Model Prediction            │
│                                       │
└─────────────────────────────────────┘
            ↑
            │
    Returns JSON Results
Integration Requirements
1. New Button in Toolbar
Add an "Analyze with IDS" button (after the Save button):

# Around line 780 in desktop_app.py toolbar setup
analyze_ids_action = QAction("🔍 Analyze with IDS", self)
analyze_ids_action.setToolTip("Send captured packets to IDS for attack detection")
analyze_ids_action.triggered.connect(self.analyze_with_ids)
self.toolbar.addAction(analyze_ids_action)
2. IDS Analysis Tab
New tab in self.details_tabs to display:

Summary Statistics Panel:

Total Flows / Attack Flows / Benign Flows
Average Confidence Score
Analysis Status (pending/complete/error)
Attack Distribution Chart:

Bar chart showing: DoS, DDoS, PortScan, Others
Percentage distribution pie chart
Top attacks by count
Detailed Results Table:

Per-flow predictions (first 100 flows)
Columns: Flow ID, Source IP, Dest IP, Predicted Label, Confidence
Color-coding by attack type
Action Buttons:

"Export Results" button
"Analyze Current PCAP" button
"Service Status" button to check IDS connectivity
New Components to Implement
Component 1: IDS Service Manager (NEW CLASS)
File: desktop_app/ids_service_manager.py

class IDSServiceManager:
    """Manages communication with Final_IDS microservice"""
    
    def __init__(self, host='localhost', port=5000):
        self.base_url = f'http://{host}:{port}'
        self.timeout = 300  # 5 minutes for large files
    
    def check_health(self) -> bool:
        """Check if IDS service is running"""
        
    def analyze_pcap(self, pcap_path: str) -> dict:
        """Send PCAP file to IDS for analysis"""
        
    def get_attack_summary(self, results: dict) -> dict:
        """Extract summary from raw API response"""
Component 2: IDS Analysis Widget (NEW CLASS)
File: desktop_app/ids_analysis_widget.py

class IDSAnalysisWidget(QWidget):
    """Widget for displaying IDS analysis results"""
    
    def __init__(self):
        self.summary_panel = ...    # Statistics display
        self.chart_panel = ...      # Attack charts
        self.results_table = ...    # Detailed results
        self.status_label = ...     # Analysis status
    
    def display_results(self, results: dict):
        """Display IDS analysis results"""
        
    def clear(self):
        """Clear all results"""
Component 3: IDS Integration in Main App (MODIFICATIONS)
File: desktop_app/desktop_app.py

Add methods:

def analyze_with_ids(self):
    """Handle Analyze with IDS button click"""
    # 1. Check if packets captured
    # 2. Save packets to temp PCAP
    # 3. Show progress dialog
    # 4. Send to IDS service
    # 5. Display results in IDS tab

def check_ids_service_status(self):
    """Verify IDS service is running"""
    
def on_ids_analysis_complete(self, results):
    """Callback when IDS analysis finishes"""
Integration Workflow
User Action                 Desktop App              IDS Service
    │                           │                        │
    │  Click "Analyze"          │                        │
    ├──────────────────────────>│                        │
    │                           │                        │
    │                      1. Save captured              │
    │                      packets to temp              │
    │                      PCAP file                    │
    │                           │                        │
    │                      2. Check service             │
    │                      health                       │
    │                           │  GET /health          │
    │                           ├──────────────────────>│
    │                           │  {"status":"healthy"} │
    │                           │<──────────────────────┤
    │                           │                        │
    │                      3. Upload PCAP &            │
    │                      show progress               │
    │                           │  POST /analyze        │
    │                           │  (multipart/form-data)│
    │                           ├──────────────────────>│
    │                           │                        │ Process PCAP:
    │                           │                        │ - CICFlowMeter
    │                           │                        │ - Feature align
    │                           │                        │ - GCN predict
    │                           │                        │
    │                           │  {"total_flows": 100, │
    │                           │   "attack_flows": 15, │
    │                           │   ...}                │
    │                           │<──────────────────────┤
    │                           │                        │
    │                      4. Parse results            │
    │                      5. Update UI                │
    │<──────────────────────────┤                        │
    │   Display results         │                        │
    ├────────────────────────┐  │                        │
    │ IDS Analysis Tab Shows │  │                        │
    │ - Attack summary       │  │                        │
    │ - Distribution charts  │  │                        │
    │ - Detailed results     │  │                        │
    └────────────────────────┘  │                        │
API Communication Details
Request to IDS Service
# Send captured packets as PCAP file
pcap_path = "captured_packets.pcap"

with open(pcap_path, 'rb') as f:
    response = requests.post(
        'http://localhost:5000/analyze',
        files={'file': f},
        timeout=300
    )

results = response.json()
IDS Service Response Format
{
  "status": "success",
  "total_flows": 100,
  "attack_flows": 15,
  "benign_flows": 85,
  "average_confidence": 0.95,
  "attack_summary": {
    "BENIGN": 85,
    "DoS": 10,
    "DDoS": 5,
    "PortScan": 0
  },
  "top_attacks": [
    {
      "attack_type": "DoS",
      "count": 10,
      "percentage": 10.0,
      "avg_confidence": 0.92
    },
    {
      "attack_type": "DDoS",
      "count": 5,
      "percentage": 5.0,
      "avg_confidence": 0.89
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
UI Design: IDS Analysis Tab
The tab should have this layout:

┌─────────────────────────────────────────────────────────┐
│ IDS Analysis Results                                    │
├─────────────────────────────────────────────────────────┤
│                                                          │
│ Status: [Analysis Complete] Last Updated: 2024-01-15  │
│                                                          │
│ ┌────────────────────────────────────────────────────┐ │
│ │ SUMMARY STATISTICS                                 │ │
│ ├────────────────────────────────────────────────────┤ │
│ │  Total Flows: 100        Attack Flows: 15         │ │
│ │  Benign Flows: 85        Avg Confidence: 0.95     │ │
│ └────────────────────────────────────────────────────┘ │
│                                                          │
│ ┌────────────────────────────────────────────────────┐ │
│ │ ATTACK DISTRIBUTION                                │ │
│ │  DoS:      10 flows (10.0%) - Confidence: 0.92    │ │
│ │  DDoS:      5 flows (5.0%)  - Confidence: 0.89    │ │
│ │  PortScan:  0 flows (0.0%)  - Confidence: N/A     │ │
│ └────────────────────────────────────────────────────┘ │
│                                                          │
│ ┌────────────────────────────────────────────────────┐ │
│ │ DETAILED RESULTS (First 100 flows)                │ │
│ │                                                    │ │
│ │ [Table with columns:]                            │ │
│ │ Source IP    | Dest IP      | Label    | Conf    │ │
│ │ ─────────────┼──────────────┼──────────┼──────── │ │
│ │ 192.168.1.5  | 10.0.0.1     | DoS      | 0.95    │ │
│ │ 192.168.1.6  | 10.0.0.2     | BENIGN   | 0.98    │ │
│ │ ...                                             │ │
│ └────────────────────────────────────────────────────┘ │
│                                                          │
│ [Check Service] [Export Results] [Clear Results]      │
│                                                          │
└─────────────────────────────────────────────────────────┘
Step-by-Step Implementation
Phase 1: Service Manager (Easy)
Create desktop_app/ids_service_manager.py
Implement HTTP communication with Final_IDS
Add error handling and timeouts
Phase 2: IDS Analysis Widget (Medium)
Create desktop_app/ids_analysis_widget.py
Design UI for results display
Add statistics panels and tables
Phase 3: Desktop App Integration (Medium)
Add "Analyze with IDS" button to toolbar
Add IDS Analysis tab to details_tabs
Implement analyze_with_ids() method
Add threading for non-blocking API calls
Connect results to widget display
Phase 4: Polish & Error Handling (Easy)
Add service health checks
Add error dialogs
Add progress dialogs
Add result export functionality
Key Implementation Considerations
Threading:

Use QThread to avoid blocking UI during IDS analysis
Show progress dialog while waiting for response
Error Handling:

Check if IDS service is running before sending
Handle network errors, timeouts, processing errors
Show user-friendly error messages
Temporary Files:

Save captured packets to temporary PCAP file
Clean up temp files after analysis
Configuration:

IDS service host/port (default: localhost:5000)
Configurable in config file or settings dialog
Questions for Clarification
Before I provide the detailed code, please confirm:

Chart Library: Which library for attack distribution charts?

Matplotlib (simple but slower)
PyQtChart (faster, native)
Other?
Detailed Results: How many flows to show by default?

First 100 (as per API)
Paginated view
Scrollable table with all results
Export Format: What export formats for results?

CSV only
CSV + PDF
CSV + Excel
IDS Service: Will it always run, or should we guide users to start it?

Auto-detect if running, show message if not
Provide "Start IDS Service" button that launches it
Would you like me to proceed with detailed code implementation for all components? I can provide:

Complete ids_service_manager.py
Complete ids_analysis_widget.py
All necessary modifications to desktop_app.py