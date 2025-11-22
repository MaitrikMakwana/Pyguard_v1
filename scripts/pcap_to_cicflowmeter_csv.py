"""
Utility to convert pcap files to CICFlowMeter-style CSV using cicflowmeter package.
Usage:
    python pcap_to_cicflowmeter_csv.py <input.pcap> <output.csv>
"""
import sys
from cicflowmeter import extract_flows
import pandas as pd

def pcap_to_csv(pcap_path, csv_path):
    flows = extract_flows(pcap_path)
    df = pd.DataFrame([flow.to_dict() for flow in flows])
    df.to_csv(csv_path, index=False)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python pcap_to_cicflowmeter_csv.py <input.pcap> <output.csv>")
        sys.exit(1)
    pcap_to_csv(sys.argv[1], sys.argv[2])
    print(f"CSV generated at {sys.argv[2]}")
