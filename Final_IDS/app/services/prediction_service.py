"""
Prediction Service - Wrapper for model predictions
"""

try:
    from app.models.gcn_model import predict_attacks
except ImportError:
    from Final_IDS.app.models.gcn_model import predict_attacks  # type: ignore


def predict_attacks_from_csv(csv_file_path, confidence_threshold=0.75):
    """
    Predict attacks from a CSV file

    Args:
        csv_file_path: Path to CSV file
        confidence_threshold: Minimum confidence to classify a flow as an attack
            (default 0.75). Lower values are more sensitive; raise to reduce false
            positives on heavy-but-legitimate traffic (video calls, backups, etc.)

    Returns:
        DataFrame with predictions
    """
    return predict_attacks(csv_file_path, confidence_threshold=confidence_threshold)


