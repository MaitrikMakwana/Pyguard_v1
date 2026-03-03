"""
PyGuard Real-World Attack Scenario Test Runner
Runs all test PCAPs through the full IDS pipeline and reports results.
"""
import sys, os, traceback, time
sys.path.insert(0, 'd:/PyGuard-main')
os.chdir('d:/PyGuard-main')

from Final_IDS.app.services.cicflowmeter_service import run_cicflowmeter
from Final_IDS.app.services.feature_alignment_service import align_csv_features
from Final_IDS.app.models.gcn_model import (
    load_model_and_preprocessors, preprocess_data, create_graph
)
import pandas as pd, numpy as np, torch, tempfile

# Load model once
print("Loading model...")
model, scaler, label_encoder, metadata, device = load_model_and_preprocessors()
print(f"Classes: {metadata['class_names']}\n")

PCAP_SCENARIOS = [
    {
        "name":     "[DOS] Real DoS Attack Traffic",
        "pcap":     r"d:/PyGuard-main/Final_IDS/Testing Files/DOS_Traffic_Files/dos.pcap",
        "expected": "DoS / DDoS",
    },
    {
        "name":     "[NORMAL] Benign Network Traffic",
        "pcap":     r"d:/PyGuard-main/Final_IDS/Testing Files/Normal_Traffic_Files/Normal.pcap",
        "expected": "BENIGN",
    },
    {
        "name":     "[MIXED] Innotech Network Capture",
        "pcap":     r"d:/PyGuard-main/Final_IDS/innotech.pcap",
        "expected": "BENIGN (majority)",
    },
    {
        "name":     "[LIVE] PyGuard Capture (live recording)",
        "pcap":     r"d:/PyGuard-main/examples/pyguard_capture.pcap",
        "expected": "Unknown",
    },
    {
        "name":     "[TEST] test4949 PCAP",
        "pcap":     r"d:/PyGuard-main/examples/test4949.pcap",
        "expected": "Unknown",
    },
]

results_summary = []
THRESHOLD = 0.75

for scenario in PCAP_SCENARIOS:
    name     = scenario["name"]
    pcap_path = scenario["pcap"]
    expected = scenario["expected"]

    print("=" * 70)
    print(f"SCENARIO: {name}")
    print(f"  PCAP    : {pcap_path}")
    print(f"  Expected: {expected}")

    if not os.path.exists(pcap_path):
        print("  SKIP: PCAP file not found\n")
        results_summary.append({"scenario": name, "status": "FILE_NOT_FOUND"})
        continue

    tmp = tempfile.mkdtemp()
    try:
        t0 = time.time()

        csv_path = run_cicflowmeter(pcap_path, tmp)

        aligned_path = os.path.join(tmp, "aligned.csv")
        align_csv_features(csv_path, aligned_path)

        df = pd.read_csv(aligned_path)
        X_scaled = preprocess_data(df.copy(), scaler, metadata['feature_columns'])
        data_graph = create_graph(X_scaled, k=metadata['k_neighbors'])
        data_graph = data_graph.to(device)

        model.eval()
        with torch.no_grad():
            out   = model(data_graph.x, data_graph.edge_index)
            preds = out.argmax(dim=1).cpu().numpy()
            probs = torch.softmax(out, dim=1).cpu().numpy()

        raw_labels = label_encoder.inverse_transform(preds)
        confs      = np.max(probs, axis=1)

        # Apply confidence threshold
        labels = raw_labels.copy()
        for i, (lbl, conf) in enumerate(zip(raw_labels, confs)):
            if lbl != 'BENIGN' and conf < THRESHOLD:
                labels[i] = 'BENIGN'

        elapsed = time.time() - t0
        total   = len(labels)

        unique, counts = np.unique(labels, return_counts=True)
        dist = {u: int(c) for u, c in zip(unique, counts)}

        benign_count = dist.get("BENIGN", 0)
        attack_count = total - benign_count
        benign_pct   = benign_count / total * 100 if total else 0
        attack_pct   = attack_count / total * 100 if total else 0
        avg_conf     = float(np.mean(confs))

        print(f"\n  RESULTS ({total} flows, processed in {elapsed:.1f}s):")
        print(f"    BENIGN     : {benign_count:5d}  ({benign_pct:.1f}%)")
        for lbl in metadata['class_names']:
            if lbl == 'BENIGN':
                continue
            cnt = dist.get(lbl, 0)
            if cnt > 0:
                mask   = labels == lbl
                avg_c  = float(np.mean(confs[mask]))
                min_c  = float(np.min(confs[mask]))
                max_c  = float(np.max(confs[mask]))
                print(f"    {lbl:10s} : {cnt:5d}  ({cnt/total*100:.1f}%)  "
                      f"avg_conf={avg_c:.3f}  min={min_c:.3f}  max={max_c:.3f}")
        print(f"    Overall avg confidence: {avg_conf:.3f}")

        # Verdict
        if attack_count == 0:
            verdict = "CLEAN - No attacks detected"
        elif attack_pct > 60:
            dominant = max((l for l in dist if l != 'BENIGN'), key=lambda l: dist.get(l, 0), default="Unknown")
            verdict  = f"HIGH THREAT - Dominant: {dominant} ({attack_pct:.1f}% of flows)"
        elif attack_pct > 20:
            verdict = f"MODERATE THREAT - {attack_pct:.1f}% attack flows"
        else:
            verdict = f"LOW/MIXED - {attack_pct:.1f}% suspicious flows (possible FP)"

        print(f"\n  VERDICT: {verdict}")

        results_summary.append({
            "scenario": name, "total": total, "benign": benign_count,
            "attacks": attack_count, "distribution": dist, "elapsed": elapsed,
            "avg_conf": avg_conf, "verdict": verdict
        })

    except Exception:
        print("  ERROR:")
        traceback.print_exc()
        results_summary.append({"scenario": name, "status": "ERROR"})
    print()

print("=" * 70)
print("FINAL SUMMARY")
print("=" * 70)
print(f"{'Scenario':<42} {'Flows':>6} {'Benign%':>8} {'Attack%':>8} {'Verdict'}")
print("-" * 70)
for r in results_summary:
    if "total" not in r:
        print(f"{r['scenario']:<42} {r.get('status','?'):>25}")
        continue
    b_pct = r['benign']  / r['total'] * 100
    a_pct = r['attacks'] / r['total'] * 100
    print(f"{r['scenario']:<42} {r['total']:>6} {b_pct:>7.1f}% {a_pct:>7.1f}%")
    print(f"  --> {r['verdict']}")
