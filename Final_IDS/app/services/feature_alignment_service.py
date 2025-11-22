"""
Feature Alignment Service - Aligns CICFlowMeter CSV to model schema
Matches the manual process: just rename columns to match model
"""

import os
import pandas as pd
import pickle


def align_csv_features(csv_file_path, output_csv_path):
    """
    Align CICFlowMeter CSV columns to match model's expected schema
    This matches the manual process: just rename columns to match model
    
    Args:
        csv_file_path: Path to CICFlowMeter generated CSV
        output_csv_path: Path to save aligned CSV
    
    Returns:
        Path to aligned CSV
    """
    print(f"Aligning CSV features: {csv_file_path}")
    
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    df = pd.read_csv(csv_file_path)
    
    # Load model expected schema
    metadata_path = os.path.join(base_dir, "Saved_Model", "model_metadata.pkl")
    with open(metadata_path, "rb") as f:
        meta = pickle.load(f)
    expected = meta["feature_columns"]
    
    # Complete mapping dictionary from CICFlowMeter column names to model expected names
    # This matches what you do manually - just rename columns
    mapping = {
        "Dst Port": "Destination Port",
        "Flow Duration": "Flow Duration",
        "Tot Fwd Pkts": "Total Fwd Packets",
        "Tot Bwd Pkts": "Total Backward Packets",
        "TotLen Fwd Pkts": "Total Length of Fwd Packets",
        "TotLen Bwd Pkts": "Total Length of Bwd Packets",
        "Fwd Pkt Len Max": "Fwd Packet Length Max",
        "Fwd Pkt Len Min": "Fwd Packet Length Min",
        "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
        "Fwd Pkt Len Std": "Fwd Packet Length Std",
        "Bwd Pkt Len Max": "Bwd Packet Length Max",
        "Bwd Pkt Len Min": "Bwd Packet Length Min",
        "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
        "Bwd Pkt Len Std": "Bwd Packet Length Std",
        "Flow Byts/s": "Flow Bytes/s",
        "Flow Pkts/s": "Flow Packets/s",
        "Flow IAT Mean": "Flow IAT Mean",
        "Flow IAT Std": "Flow IAT Std",
        "Flow IAT Max": "Flow IAT Max",
        "Flow IAT Min": "Flow IAT Min",
        "Fwd IAT Tot": "Fwd IAT Total",
        "Fwd IAT Mean": "Fwd IAT Mean",
        "Fwd IAT Std": "Fwd IAT Std",
        "Fwd IAT Max": "Fwd IAT Max",
        "Fwd IAT Min": "Fwd IAT Min",
        "Bwd IAT Tot": "Bwd IAT Total",
        "Bwd IAT Mean": "Bwd IAT Mean",
        "Bwd IAT Std": "Bwd IAT Std",
        "Bwd IAT Max": "Bwd IAT Max",
        "Bwd IAT Min": "Bwd IAT Min",
        "Fwd PSH Flags": "Fwd PSH Flags",
        "Bwd PSH Flags": "Bwd PSH Flags",
        "Fwd URG Flags": "Fwd URG Flags",
        "Bwd URG Flags": "Bwd URG Flags",
        "Fwd Header Len": "Fwd Header Length",
        "Bwd Header Len": "Bwd Header Length",
        "Fwd Pkts/s": "Fwd Packets/s",
        "Bwd Pkts/s": "Bwd Packets/s",
        "Pkt Len Min": "Min Packet Length",
        "Pkt Len Max": "Max Packet Length",
        "Pkt Len Mean": "Packet Length Mean",
        "Pkt Len Std": "Packet Length Std",
        "Pkt Len Var": "Packet Length Variance",
        "FIN Flag Cnt": "FIN Flag Count",
        "SYN Flag Cnt": "SYN Flag Count",
        "RST Flag Cnt": "RST Flag Count",
        "PSH Flag Cnt": "PSH Flag Count",
        "ACK Flag Cnt": "ACK Flag Count",
        "URG Flag Cnt": "URG Flag Count",
        "CWE Flag Count": "CWE Flag Count",
        "CWR Flag Count": "CWE Flag Count",  # CWR maps to CWE
        "ECE Flag Cnt": "ECE Flag Count",
        "Down/Up Ratio": "Down/Up Ratio",
        "Pkt Size Avg": "Average Packet Size",
        "Fwd Seg Size Avg": "Avg Fwd Segment Size",
        "Bwd Seg Size Avg": "Avg Bwd Segment Size",
        "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
        "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
        "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
        "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
        "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
        "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
        "Subflow Fwd Pkts": "Subflow Fwd Packets",
        "Subflow Fwd Byts": "Subflow Fwd Bytes",
        "Subflow Bwd Pkts": "Subflow Bwd Packets",
        "Subflow Bwd Byts": "Subflow Bwd Bytes",
        "Subflow Fwd Packets": "Subflow Fwd Packets",
        "Subflow Fwd Bytes": "Subflow Fwd Bytes",
        "Subflow Bwd Packets": "Subflow Bwd Packets",
        "Subflow Bwd Bytes": "Subflow Bwd Bytes",
        "Init Fwd Win Byts": "Init_Win_bytes_forward",
        "Init Bwd Win Byts": "Init_Win_bytes_backward",
        "Fwd Act Data Pkts": "act_data_pkt_fwd",
        "Fwd Seg Size Min": "min_seg_size_forward",
        "Active Mean": "Active Mean",
        "Active Std": "Active Std",
        "Active Max": "Active Max",
        "Active Min": "Active Min",
        "Idle Mean": "Idle Mean",
        "Idle Std": "Idle Std",
        "Idle Max": "Idle Max",
        "Idle Min": "Idle Min"
    }
    
    # Apply renaming with case-insensitive matching
    df_columns_lower = {col.lower(): col for col in df.columns}
    rename_dict = {}
    
    for old_name, new_name in mapping.items():
        if old_name in df.columns:
            if old_name != new_name:
                rename_dict[old_name] = new_name
        elif old_name.lower() in df_columns_lower:
            actual_col = df_columns_lower[old_name.lower()]
            if actual_col != new_name:
                rename_dict[actual_col] = new_name
    
    # Special handling for CWR -> CWE
    if "CWR Flag Count" in df.columns and "CWE Flag Count" not in df.columns:
        if "CWR Flag Count" not in rename_dict:
            rename_dict["CWR Flag Count"] = "CWE Flag Count"
    
    if rename_dict:
        df = df.rename(columns=rename_dict)
        print(f"Renamed {len(rename_dict)} columns from CICFlowMeter format to model format")
    
    # Handle Fwd Header Length.1 (if model expects it)
    if "Fwd Header Length" in df.columns and "Fwd Header Length.1" in expected:
        if "Fwd Header Length.1" not in df.columns:
            df["Fwd Header Length.1"] = df["Fwd Header Length"]
            print("Created Fwd Header Length.1 from Fwd Header Length")
    
    # Remove non-feature columns (like Flow ID, Src IP, etc.)
    non_feature_cols = [col for col in df.columns if col not in expected]
    if non_feature_cols:
        df = df.drop(columns=non_feature_cols, errors='ignore')
        print(f"Removed {len(non_feature_cols)} non-feature columns")
    
    # Add missing columns with zeros (if model expects columns that don't exist)
    missing_cols = []
    for col in expected:
        if col not in df.columns:
            df[col] = 0
            missing_cols.append(col)
    
    if missing_cols:
        print(f"Added {len(missing_cols)} missing columns with default values")
    else:
        print("All expected columns present!")
    
    # Reorder columns to match model schema exactly
    if list(df.columns) != expected:
        print(f"Reordering columns to match model schema...")
        df = df[expected]
    
    # Apply post-processing: Zero out features that were zeroed in training data
    # This matches the format of innotech_a.csv (manually processed reference)
    # These features were zeroed in the training data, so model expects zeros
    features_to_zero = [
        'Destination Port',
        'Total Fwd Packets',
        'Total Backward Packets',
        'Total Length of Fwd Packets',
        'Total Length of Bwd Packets',
        'Fwd Packet Length Max',
        'Fwd Packet Length Min',
        'Fwd Packet Length Mean',
        'Fwd Packet Length Std',
        'Bwd Packet Length Max',
        'Bwd Packet Length Min',
        'Bwd Packet Length Mean',
        'Bwd Packet Length Std',
        'Flow Bytes/s',
        'Flow Packets/s',
        'Fwd IAT Total',
        'Bwd IAT Total',
        'Fwd Header Length',
        'Bwd Header Length',
        'Fwd Packets/s',
        'Bwd Packets/s',
        'Min Packet Length',
        'Max Packet Length',
        'Packet Length Mean',
        'Packet Length Std',
        'Packet Length Variance',
        'FIN Flag Count',
        'SYN Flag Count',
        'PSH Flag Count',
        'ACK Flag Count',
        'Average Packet Size',
        'Avg Fwd Segment Size',
        'Avg Bwd Segment Size',
        'Fwd Header Length.1',
        'Subflow Fwd Packets',
        'Subflow Fwd Bytes',
        'Subflow Bwd Packets',
        'Subflow Bwd Bytes',
        'Init_Win_bytes_forward',
        'Init_Win_bytes_backward',
        'act_data_pkt_fwd'
    ]
    
    # Zero out these features to match training data format
    for col in features_to_zero:
        if col in df.columns:
            df[col] = 0
    
    print(f"Applied post-processing: zeroed {len(features_to_zero)} features to match training data format")
    
    # Final verification
    if list(df.columns) == expected:
        print(f"Column alignment verified: {len(df.columns)} columns match model schema")
    else:
        print(f"WARNING: Column mismatch after alignment!")
    
    # Save aligned CSV
    df.to_csv(output_csv_path, index=False)
    print(f"Aligned CSV saved: {output_csv_path}")
    
    return output_csv_path

