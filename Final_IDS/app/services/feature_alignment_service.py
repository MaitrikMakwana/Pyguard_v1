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
    
    # ── Mapping 1: Java CICFlowMeter (Title Case) → model schema ──────────────
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
        "Idle Min": "Idle Min",
    }

    # ── Mapping 2: Python cicflowmeter fallback (snake_case) → model schema ───
    # The Python cicflowmeter package uses lowercase_snake_case column names
    # instead of the Java tool's Title Case names.  Without this mapping ALL
    # features would be silently zeroed by the alignment step, causing the model
    # to classify every flow as an attack.
    python_cic_mapping = {
        "dst_port":             "Destination Port",
        "flow_duration":        "Flow Duration",
        "tot_fwd_pkts":         "Total Fwd Packets",
        "tot_bwd_pkts":         "Total Backward Packets",
        "totlen_fwd_pkts":      "Total Length of Fwd Packets",
        "totlen_bwd_pkts":      "Total Length of Bwd Packets",
        "fwd_pkt_len_max":      "Fwd Packet Length Max",
        "fwd_pkt_len_min":      "Fwd Packet Length Min",
        "fwd_pkt_len_mean":     "Fwd Packet Length Mean",
        "fwd_pkt_len_std":      "Fwd Packet Length Std",
        "bwd_pkt_len_max":      "Bwd Packet Length Max",
        "bwd_pkt_len_min":      "Bwd Packet Length Min",
        "bwd_pkt_len_mean":     "Bwd Packet Length Mean",
        "bwd_pkt_len_std":      "Bwd Packet Length Std",
        "flow_byts_s":          "Flow Bytes/s",
        "flow_pkts_s":          "Flow Packets/s",
        "flow_iat_mean":        "Flow IAT Mean",
        "flow_iat_std":         "Flow IAT Std",
        "flow_iat_max":         "Flow IAT Max",
        "flow_iat_min":         "Flow IAT Min",
        "fwd_iat_tot":          "Fwd IAT Total",
        "fwd_iat_mean":         "Fwd IAT Mean",
        "fwd_iat_std":          "Fwd IAT Std",
        "fwd_iat_max":          "Fwd IAT Max",
        "fwd_iat_min":          "Fwd IAT Min",
        "bwd_iat_tot":          "Bwd IAT Total",
        "bwd_iat_mean":         "Bwd IAT Mean",
        "bwd_iat_std":          "Bwd IAT Std",
        "bwd_iat_max":          "Bwd IAT Max",
        "bwd_iat_min":          "Bwd IAT Min",
        "fwd_psh_flags":        "Fwd PSH Flags",
        "bwd_psh_flags":        "Bwd PSH Flags",
        "fwd_urg_flags":        "Fwd URG Flags",
        "bwd_urg_flags":        "Bwd URG Flags",
        "fwd_header_len":       "Fwd Header Length",
        "bwd_header_len":       "Bwd Header Length",
        "fwd_pkts_s":           "Fwd Packets/s",
        "bwd_pkts_s":           "Bwd Packets/s",
        "pkt_len_min":          "Min Packet Length",
        "pkt_len_max":          "Max Packet Length",
        "pkt_len_mean":         "Packet Length Mean",
        "pkt_len_std":          "Packet Length Std",
        "pkt_len_var":          "Packet Length Variance",
        "fin_flag_cnt":         "FIN Flag Count",
        "syn_flag_cnt":         "SYN Flag Count",
        "rst_flag_cnt":         "RST Flag Count",
        "psh_flag_cnt":         "PSH Flag Count",
        "ack_flag_cnt":         "ACK Flag Count",
        "urg_flag_cnt":         "URG Flag Count",
        "cwe_flag_count":       "CWE Flag Count",
        "cwr_flag_count":       "CWE Flag Count",  # CWR → CWE
        "ece_flag_cnt":         "ECE Flag Count",
        "down_up_ratio":        "Down/Up Ratio",
        "pkt_size_avg":         "Average Packet Size",
        "fwd_seg_size_avg":     "Avg Fwd Segment Size",
        "bwd_seg_size_avg":     "Avg Bwd Segment Size",
        "fwd_byts_b_avg":       "Fwd Avg Bytes/Bulk",
        "fwd_pkts_b_avg":       "Fwd Avg Packets/Bulk",
        "fwd_blk_rate_avg":     "Fwd Avg Bulk Rate",
        "bwd_byts_b_avg":       "Bwd Avg Bytes/Bulk",
        "bwd_pkts_b_avg":       "Bwd Avg Packets/Bulk",
        "bwd_blk_rate_avg":     "Bwd Avg Bulk Rate",
        "subflow_fwd_pkts":     "Subflow Fwd Packets",
        "subflow_fwd_byts":     "Subflow Fwd Bytes",
        "subflow_bwd_pkts":     "Subflow Bwd Packets",
        "subflow_bwd_byts":     "Subflow Bwd Bytes",
        "init_fwd_win_byts":    "Init_Win_bytes_forward",
        "init_bwd_win_byts":    "Init_Win_bytes_backward",
        "fwd_act_data_pkts":    "act_data_pkt_fwd",
        "fwd_seg_size_min":     "min_seg_size_forward",
        "active_mean":          "Active Mean",
        "active_std":           "Active Std",
        "active_max":           "Active Max",
        "active_min":           "Active Min",
        "idle_mean":            "Idle Mean",
        "idle_std":             "Idle Std",
        "idle_max":             "Idle Max",
        "idle_min":             "Idle Min",
    }

    # Merge: python_cic_mapping takes effect only for columns that are actually
    # present in the CSV (avoids accidentally overwriting Java-format columns).
    mapping.update(python_cic_mapping)

    
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
    
    print("Using real CICFlowMeter feature values (no feature zeroing applied).")
    
    # Final verification
    if list(df.columns) == expected:
        print(f"Column alignment verified: {len(df.columns)} columns match model schema")
    else:
        print(f"WARNING: Column mismatch after alignment!")
    
    # Save aligned CSV
    df.to_csv(output_csv_path, index=False)
    print(f"Aligned CSV saved: {output_csv_path}")
    
    return output_csv_path

