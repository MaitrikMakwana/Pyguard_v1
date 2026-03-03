"""
GCN Model for Attack Detection
"""

import pandas as pd
import numpy as np
import torch
import torch.nn.functional as F
from sklearn.neighbors import kneighbors_graph
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv
import joblib
import pickle
import os


class GCN(torch.nn.Module):
    """Graph Convolutional Network for attack detection"""
    
    def __init__(self, in_feats, hid_feats, num_classes):
        super().__init__()
        self.conv1 = GCNConv(in_feats, hid_feats)
        self.conv2 = GCNConv(hid_feats, hid_feats)
        self.lin = torch.nn.Linear(hid_feats, num_classes)

    def forward(self, x, edge_index):
        x = F.relu(self.conv1(x, edge_index))
        x = F.relu(self.conv2(x, edge_index))
        return F.log_softmax(self.lin(x), dim=1)


def load_model_and_preprocessors():
    """Load the trained model and all preprocessors"""
    print("Loading model and preprocessors...")

    base_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "Saved_Model")

    required_files = [
        'gcn_model_complete.pth',
        'scaler.pkl',
        'label_encoder.pkl',
        'model_metadata.pkl'
    ]

    for file in required_files:
        file_path = os.path.join(base_path, file)
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Required file '{file}' not found in {base_path}")

    with open(os.path.join(base_path, 'model_metadata.pkl'), 'rb') as f:
        metadata = pickle.load(f)

    scaler = joblib.load(os.path.join(base_path, 'scaler.pkl'))
    label_encoder = joblib.load(os.path.join(base_path, 'label_encoder.pkl'))

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    
    try:
        import sys
        if '__main__' in sys.modules:
            sys.modules['__main__'].GCN = GCN
        sys.modules[__name__].GCN = GCN
        
        model = torch.load(os.path.join(base_path, "gcn_model_complete.pth"), map_location=device, weights_only=False)
        print("Loaded complete model directly")
    except (AttributeError, RuntimeError, KeyError) as e:
        print(f"Warning: Could not load complete model directly: {e}")
        print("Attempting alternative loading method...")
        
        try:
            import __main__
            __main__.GCN = GCN
            model = torch.load(os.path.join(base_path, "gcn_model_complete.pth"), map_location=device, weights_only=False)
            print("Loaded complete model using alternative method")
        except Exception as e2:
            print(f"Alternative method failed: {e2}")
            print("Rebuilding model from architecture and state dict...")
            
            num_features = metadata['num_features']
            num_classes = metadata['num_classes']
            hidden_features = metadata.get('hidden_features', 64)
            
            model = GCN(num_features, hidden_features, num_classes)
            
            state_dict_path = os.path.join(base_path, "gcn_model.pth")
            if os.path.exists(state_dict_path):
                state_dict = torch.load(state_dict_path, map_location=device)
                model.load_state_dict(state_dict)
                print("Loaded model from state dict")
            else:
                raise FileNotFoundError(f"Could not find state dict at {state_dict_path}")
    
    model.eval()

    print(f"Model loaded successfully on device: {device}")
    print(f"Number of classes: {metadata['num_classes']}")
    print(f"Class names: {metadata['class_names']}")

    return model, scaler, label_encoder, metadata, device


def preprocess_data(df, scaler, feature_columns):
    """Preprocess the input data"""
    print("Preprocessing data...")

    df.columns = df.columns.str.strip()
    df.fillna(0, inplace=True)
    df.replace([np.inf, -np.inf], 0, inplace=True)

    column_mapping = {
        "CWR Flag Count": "CWE Flag Count",
        "ECE Flag Cnt": "ECE Flag Count",
        "Subflow Fwd Pkts": "Subflow Fwd Packets",
        "Subflow Fwd Byts": "Subflow Fwd Bytes",
        "Subflow Bwd Pkts": "Subflow Bwd Packets",
        "Subflow Bwd Byts": "Subflow Bwd Bytes",
    }
    
    rename_dict = {}
    for old_name, new_name in column_mapping.items():
        if old_name in df.columns and new_name not in df.columns:
            rename_dict[old_name] = new_name
    
    if rename_dict:
        df = df.rename(columns=rename_dict)
        print(f"Mapped {len(rename_dict)} column name variations: {list(rename_dict.keys())}")

    available_features = [col for col in feature_columns if col in df.columns]
    missing_features = [col for col in feature_columns if col not in df.columns]

    if missing_features:
        print(f"Warning: Missing features: {missing_features}")
        for feature in missing_features:
            df[feature] = 0

    X = df[feature_columns].values
    X_scaled = scaler.transform(X)

    return X_scaled


def create_graph(X_scaled, k=10):
    """Create graph structure from features"""
    print(f"Creating graph with k={k} neighbors...")

    num_nodes = len(X_scaled)
    if num_nodes == 0:
        raise ValueError("No samples available to build the graph.")

    if num_nodes == 1:
        edge_index = torch.empty((2, 0), dtype=torch.long)
        data = Data(
            x=torch.tensor(X_scaled, dtype=torch.float),
            edge_index=edge_index
        )
        print("Graph created: 1 node, 0 edges (single-sample fallback)")
        return data

    k = max(1, min(k, num_nodes - 1))
    A = kneighbors_graph(
        X_scaled,
        n_neighbors=k,
        mode='connectivity',
        include_self=False
    ).tocoo()
    edge_index = torch.tensor([A.row, A.col], dtype=torch.long)

    data = Data(
        x=torch.tensor(X_scaled, dtype=torch.float),
        edge_index=edge_index
    )

    print(f"Graph created: {data.num_nodes} nodes, {data.num_edges // 2} undirected edges")
    return data


def predict_attacks(csv_file_path, output_file=None, confidence_threshold=0.75):
    """
    Predict attack types from a CSV file

    Args:
        csv_file_path (str): Path to the CSV file containing network traffic data
        output_file (str, optional): Path to save predictions
        confidence_threshold (float): Minimum confidence required to label a flow as
            an attack.  Flows predicted as non-BENIGN but with confidence below this
            threshold are reclassified as BENIGN to reduce false positives.
            Range 0.0–1.0, default 0.75.

    Returns:
        DataFrame with original data and predictions
    """
    model, scaler, label_encoder, metadata, device = load_model_and_preprocessors()

    print(f"Loading data from: {csv_file_path}")
    df = pd.read_csv(csv_file_path)
    print(f"Data shape: {df.shape}")

    df_original = df.copy()
    X_scaled = preprocess_data(df, scaler, metadata['feature_columns'])
    data = create_graph(X_scaled, k=metadata['k_neighbors'])
    data = data.to(device)

    print("Making predictions...")
    model.eval()
    with torch.no_grad():
        out = model(data.x, data.edge_index)
        predictions = out.argmax(dim=1).cpu().numpy()
        probabilities = torch.softmax(out, dim=1).cpu().numpy()

    predicted_labels = label_encoder.inverse_transform(predictions)
    confidence_scores = np.max(probabilities, axis=1)

    # ── Confidence threshold filter ─────────────────────────────────────────
    # Flows predicted as an attack but with low confidence are very likely
    # legitimate heavy traffic (e.g. video calls, large downloads) that shares
    # some timing patterns with DoS.  Reclassify them as BENIGN.
    for i, (label, conf) in enumerate(zip(predicted_labels, confidence_scores)):
        if label != 'BENIGN' and conf < confidence_threshold:
            predicted_labels[i] = 'BENIGN'
    # ────────────────────────────────────────────────────────────────────────

    results_df = df_original.copy()
    results_df['Predicted_Label'] = predicted_labels
    results_df['Confidence'] = confidence_scores

    for i, class_name in enumerate(metadata['class_names']):
        results_df[f'Prob_{class_name}'] = probabilities[:, i]

    print("\nPrediction Summary:")
    print(f"Total samples: {len(predictions)}")
    print("\nPredicted label distribution:")
    print(pd.Series(predicted_labels).value_counts())

    print(f"\nAverage confidence: {np.mean(confidence_scores):.4f}")
    print(f"Min confidence: {np.min(confidence_scores):.4f}")
    print(f"Max confidence: {np.max(confidence_scores):.4f}")

    if output_file:
        results_df.to_csv(output_file, index=False)
        print(f"\nResults saved to: {output_file}")

    return results_df

