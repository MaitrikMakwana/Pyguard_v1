"""
PyGuard Full Attack Scenario Validation
Uses the retrained model + custom flow extractor on all 6 labeled PCAPs.
"""
import sys, os, traceback, time, tempfile
sys.path.insert(0, 'd:/PyGuard-main')
sys.path.insert(0, 'd:/PyGuard-main/scripts')
os.chdir('d:/PyGuard-main')

from Final_IDS.app.models.gcn_model import load_model_and_preprocessors, preprocess_data, create_graph
from scripts.pyguard_flow_extractor import extract_flows_from_pcap
import pandas as pd, numpy as np, torch

print("Loading retrained model...")
model, scaler, label_encoder, metadata, device = load_model_and_preprocessors()
print(f"Classes: {metadata['class_names']}")
print(f"Trained on: {metadata.get('training_samples','?')} samples, accuracy: {metadata.get('test_accuracy',0):.1f}%\n")

PCAP_SCENARIOS = [
    {"name": "[BENIGN]   benign_traffic.pcap",    "pcap": r"d:/PyGuard-main/Final_IDS/Testing Files/benign_traffic.pcap",    "expected": "BENIGN"},
    {"name": "[DoS]      dos_syn_flood.pcap",      "pcap": r"d:/PyGuard-main/Final_IDS/Testing Files/dos_syn_flood.pcap",      "expected": "DoS"},
    {"name": "[DoS]      dos_udp_flood.pcap",      "pcap": r"d:/PyGuard-main/Final_IDS/Testing Files/dos_udp_flood.pcap",      "expected": "DoS"},
    {"name": "[DoS]      dos_slowloris.pcap",      "pcap": r"d:/PyGuard-main/Final_IDS/Testing Files/dos_slowloris.pcap",      "expected": "DoS"},
    {"name": "[DDoS]     ddos_multihost.pcap",     "pcap": r"d:/PyGuard-main/Final_IDS/Testing Files/ddos_multihost.pcap",     "expected": "DDoS"},
    {"name": "[PortScan] portscan.pcap",           "pcap": r"d:/PyGuard-main/Final_IDS/Testing Files/portscan.pcap",           "expected": "PortScan"},
    {"name": "[BENIGN]   Normal.pcap (existing)",  "pcap": r"d:/PyGuard-main/Final_IDS/Testing Files/Normal_Traffic_Files/Normal.pcap","expected": "BENIGN"},
    {"name": "[DoS]      dos.pcap (existing)",     "pcap": r"d:/PyGuard-main/Final_IDS/Testing Files/DOS_Traffic_Files/dos.pcap","expected": "DoS"},
]

THRESHOLD = 0.75
results  = []

for s in PCAP_SCENARIOS:
    name, pcap_path, expected = s["name"], s["pcap"], s["expected"]
    print("="*65)
    print(f"  {name}")
    if not os.path.exists(pcap_path):
        print("    SKIP: file not found"); results.append((name, expected, "SKIP", 0, "")); continue
    try:
        tmp = tempfile.mkdtemp()
        t0  = time.time()
        csv_path = extract_flows_from_pcap(pcap_path, tmp)
        df = pd.read_csv(csv_path)
        if df.empty:
            print("    No flows extracted"); results.append((name, expected, "NO_FLOWS", 0, "")); continue

        X = preprocess_data(df.copy(), scaler, metadata['feature_columns'])
        g = create_graph(X, k=metadata['k_neighbors']).to(device)
        model.eval()
        with torch.no_grad():
            out   = model(g.x, g.edge_index)
            preds = out.argmax(dim=1).cpu().numpy()
            probs = torch.softmax(out, dim=1).cpu().numpy()
        raw_labels = label_encoder.inverse_transform(preds)
        confs      = np.max(probs, axis=1)

        # Apply confidence threshold
        labels = raw_labels.copy()
        for i, (lbl, conf) in enumerate(zip(raw_labels, confs)):
            if lbl != 'BENIGN' and conf < THRESHOLD:
                labels[i] = 'BENIGN'

        total = len(labels)
        unique, counts = np.unique(labels, return_counts=True)
        dist = {u: int(c) for u, c in zip(unique, counts)}
        top_label = max(dist, key=dist.get)
        top_pct   = dist[top_label] / total * 100
        elapsed   = time.time() - t0

        # Determine pass/fail
        # Pass if expected class is majority OR >= 50% for attack scenarios
        pass_mark = top_label == expected or (dist.get(expected, 0) / total) >= 0.5
        status    = "PASS" if pass_mark else "FAIL"

        print(f"    Flows: {total}  |  Time: {elapsed:.1f}s")
        for lbl in metadata['class_names']:
            cnt = dist.get(lbl, 0)
            if cnt > 0:
                bar = '#' * int(cnt/total*30)
                print(f"    {lbl:<12} {cnt:5d} ({cnt/total*100:5.1f}%) {bar}")
        print(f"    Dominant: {top_label} ({top_pct:.1f}%)  Expected: {expected}  [{status}]")
        results.append((name, expected, status, total, top_label))
    except Exception:
        traceback.print_exc()
        results.append((name, expected, "ERROR", 0, ""))

print("\n" + "="*65)
print("FINAL VALIDATION REPORT")
print("="*65)
passes = sum(1 for r in results if r[2]=="PASS")
total_tests = sum(1 for r in results if r[2] not in ("SKIP","NO_FLOWS","ERROR"))
print(f"\n  Score: {passes}/{total_tests} tests passed")
print()
print(f"{'Scenario':<42} {'Expected':<12} {'Result':<10} {'Dominant'}")
print("-"*78)
for name, exp, status, total, dominant in results:
    mark = "OK" if status=="PASS" else ("--" if status in ("SKIP","NO_FLOWS") else "XX")
    print(f"  [{mark}] {name:<40} {exp:<12} {status:<10} {dominant or '-'}")
