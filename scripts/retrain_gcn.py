"""
PyGuard GCN Model Retraining Script
=====================================
Retrains the GCN on:
  1. Existing labeled CSVs from Testing Files/
  2. Synthetic flow CSVs extracted from generated attack PCAPs

Run:
    python scripts/retrain_gcn.py

Outputs (overwrites Saved_Model/):
   gcn_model_complete.pth
   scaler.pkl
   label_encoder.pkl
   model_metadata.pkl
"""

import os, sys, pickle, math, time, tempfile
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import torch
import torch.nn.functional as F
from torch.nn import Linear
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.neighbors import kneighbors_graph
import scipy.sparse as sp

# Try torch_geometric
try:
    from torch_geometric.nn import GCNConv
    from torch_geometric.data import Data
    HAS_TG = True
except ImportError:
    HAS_TG = False
    print("WARNING: torch_geometric not available — using simple GCN fallback")

from scripts.pyguard_flow_extractor import extract_flows_from_pcap, MODEL_COLUMNS

# ─────────────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR   = os.path.dirname(BASE_DIR)
SAVED_DIR  = os.path.join(ROOT_DIR, "Final_IDS", "Saved_Model")
TESTING    = os.path.join(ROOT_DIR, "Final_IDS", "Testing Files")
K_NEIGHBORS = 10
HIDDEN      = 64
EPOCHS      = 80
LR          = 0.005
SAMPLES_PER_CLASS = 2000    # max rows sampled per class for balance

# ─────────────────────────────────────────────────────────────────────────────
# Attack label map for synthetic PCAPs
PCAP_LABELS = {
    "benign_traffic.pcap":  "BENIGN",
    "dos_syn_flood.pcap":   "DoS",
    "dos_udp_flood.pcap":   "DoS",
    "dos_slowloris.pcap":   "DoS",
    "ddos_multihost.pcap":  "DDoS",
    "portscan.pcap":        "PortScan",
    "dos.pcap":             "DoS",
    "Normal.pcap":          "BENIGN",
}

# Existing labeled CSVs
CSV_LABELS = {
    "NormalT_a.csv":  "BENIGN",
    "dos_7_fixed.csv": "DoS",
}

# ─────────────────────────────────────────────────────────────────────────────
def load_all_data():
    frames = []
    tmp = tempfile.mkdtemp()

    # 1. Existing labeled CSVs
    for csv_file, label in CSV_LABELS.items():
        for root, _, files in os.walk(TESTING):
            if csv_file in files:
                path = os.path.join(root, csv_file)
                print(f"  Loading CSV {csv_file} ({label}) ...")
                df = pd.read_csv(path)
                df["Label"] = label
                frames.append(df)

    # 2. Synthetic and existing PCAPs
    pcap_search_dirs = [
        TESTING,
        os.path.join(TESTING, "DOS_Traffic_Files"),
        os.path.join(TESTING, "Normal_Traffic_Files"),
        os.path.join(ROOT_DIR, "Final_IDS"),
    ]
    for search_dir in pcap_search_dirs:
        if not os.path.isdir(search_dir):
            continue
        for fname in os.listdir(search_dir):
            if not fname.endswith(".pcap"):
                continue
            label = PCAP_LABELS.get(fname)
            if label is None:
                continue
            pcap_path = os.path.join(search_dir, fname)
            print(f"  Extracting flows from {fname} ({label}) ...")
            try:
                csv_path = extract_flows_from_pcap(pcap_path, tmp)
                df = pd.read_csv(csv_path)
                df["Label"] = label
                frames.append(df)
            except Exception as e:
                print(f"    SKIP {fname}: {e}")

    if not frames:
        raise RuntimeError("No training data found!")

    full = pd.concat(frames, ignore_index=True)
    print(f"\n  Loaded {len(full)} total rows before balancing")
    return full


def build_features(df):
    """Align, clean, and return X, y."""
    for c in MODEL_COLUMNS:
        if c not in df.columns:
            df[c] = 0.0
        else:
            # Force numeric — existing CSVs may have object/string columns
            df[c] = pd.to_numeric(df[c], errors="coerce")

    df = df[MODEL_COLUMNS + ["Label"]].copy()
    df.replace([float("inf"), float("-inf")], 0, inplace=True)
    df.fillna(0, inplace=True)

    # Balance classes
    balanced = []
    for label, grp in df.groupby("Label"):
        n = min(len(grp), SAMPLES_PER_CLASS)
        balanced.append(grp.sample(n, random_state=42))
    df = pd.concat(balanced, ignore_index=True).sample(frac=1, random_state=42)
    print(f"\n  After balancing: {len(df)} rows")
    print(df["Label"].value_counts().to_string())

    X = df[MODEL_COLUMNS].values.astype(np.float32)
    y = df["Label"].values
    return X, y


# ─────────────────────────────────────────────────────────────────────────────
# GCN Model
# ─────────────────────────────────────────────────────────────────────────────
if HAS_TG:
    class GCN(torch.nn.Module):
        def __init__(self, in_feats, hid_feats, num_classes):
            super().__init__()
            self.conv1 = GCNConv(in_feats, hid_feats)
            self.conv2 = GCNConv(hid_feats, hid_feats)
            self.lin   = Linear(hid_feats, num_classes)

        def forward(self, x, edge_index):
            x = F.relu(self.conv1(x, edge_index))
            x = F.dropout(x, p=0.3, training=self.training)
            x = F.relu(self.conv2(x, edge_index))
            return self.lin(x)

    def build_graph(X_scaled, k=K_NEIGHBORS):
        A = kneighbors_graph(X_scaled, k, mode="connectivity",
                             include_self=False).tocoo()
        edge_index = torch.tensor(
            np.vstack([A.row, A.col]), dtype=torch.long
        )
        x = torch.tensor(X_scaled, dtype=torch.float)
        return Data(x=x, edge_index=edge_index)


# ─────────────────────────────────────────────────────────────────────────────
def train():
    print("="*65)
    print("PyGuard GCN Retraining")
    print("="*65)

    print("\n[1/5] Loading data ...")
    raw_df = load_all_data()
    X_raw, y_raw = build_features(raw_df)

    print("\n[2/5] Preprocessing ...")
    le    = LabelEncoder()
    y_enc = le.fit_transform(y_raw)
    num_classes = len(le.classes_)
    print(f"  Classes: {list(le.classes_)}")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)

    Xtr, Xte, ytr, yte = train_test_split(
        X_scaled, y_enc, test_size=0.2, random_state=42, stratify=y_enc
    )
    print(f"  Train: {len(Xtr)}, Test: {len(Xte)}")

    if not HAS_TG:
        print("\n  torch_geometric not available — cannot train GCN.")
        print("  Install it: pip install torch_geometric")
        return

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n[3/5] Building graphs (device={device}) ...")
    train_data = build_graph(Xtr).to(device)
    test_data  = build_graph(Xte).to(device)
    train_y    = torch.tensor(ytr, dtype=torch.long).to(device)
    test_y     = torch.tensor(yte, dtype=torch.long).to(device)

    in_feats = X_scaled.shape[1]
    model = GCN(in_feats, HIDDEN, num_classes).to(device)
    opt   = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=5e-4)
    scheduler = torch.optim.lr_scheduler.StepLR(opt, step_size=30, gamma=0.5)

    print(f"\n[4/5] Training for {EPOCHS} epochs ...")
    best_acc = 0.0
    best_state = None

    for epoch in range(1, EPOCHS + 1):
        model.train()
        opt.zero_grad()
        out  = model(train_data.x, train_data.edge_index)
        loss = F.cross_entropy(out, train_y)
        loss.backward()
        opt.step()
        scheduler.step()

        if epoch % 10 == 0 or epoch == 1:
            model.eval()
            with torch.no_grad():
                pred = model(test_data.x, test_data.edge_index).argmax(dim=1)
                acc  = (pred == test_y).float().mean().item() * 100
            if acc > best_acc:
                best_acc   = acc
                best_state = {k: v.clone() for k, v in model.state_dict().items()}
            print(f"  Epoch {epoch:3d}  loss={loss.item():.4f}  test_acc={acc:.1f}%  "
                  f"(best={best_acc:.1f}%)")

    if best_state:
        model.load_state_dict(best_state)

    # Final accuracy report
    model.eval()
    with torch.no_grad():
        pred = model(test_data.x, test_data.edge_index).argmax(dim=1)
        final_acc = (pred == test_y).float().mean().item() * 100
    print(f"\n  Final test accuracy: {final_acc:.2f}%")

    print("\n[5/5] Saving model ...")
    os.makedirs(SAVED_DIR, exist_ok=True)

    # Save full model
    torch.save(model, os.path.join(SAVED_DIR, "gcn_model_complete.pth"))
    # Save state dict
    torch.save(model.state_dict(), os.path.join(SAVED_DIR, "gcn_model.pth"))

    import joblib
    joblib.dump(scaler, os.path.join(SAVED_DIR, "scaler.pkl"))
    joblib.dump(le,     os.path.join(SAVED_DIR, "label_encoder.pkl"))

    metadata = {
        "num_features":   in_feats,
        "num_classes":    num_classes,
        "class_names":    list(le.classes_),
        "feature_columns": MODEL_COLUMNS,
        "k_neighbors":    K_NEIGHBORS,
        "hidden_features": HIDDEN,
        "trained_at":     time.strftime("%Y-%m-%d %H:%M:%S"),
        "training_samples": len(Xtr),
        "test_accuracy":  final_acc,
    }
    with open(os.path.join(SAVED_DIR, "model_metadata.pkl"), "wb") as f:
        pickle.dump(metadata, f)

    print(f"  Model saved to: {SAVED_DIR}")
    print(f"  Classes: {list(le.classes_)}")
    print(f"  Test accuracy: {final_acc:.2f}%")
    print("\nDone!")


if __name__ == "__main__":
    train()
