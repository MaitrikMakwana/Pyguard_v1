"""
Prediction Service - Wrapper for model predictions
"""

try:
    from app.models.gcn_model import predict_attacks
except ImportError:
    from Final_IDS.app.models.gcn_model import predict_attacks  # type: ignore


def predict_attacks_from_csv(csv_file_path):
    """
    Predict attacks from a CSV file
    
    Args:
        csv_file_path: Path to CSV file
    
    Returns:
        DataFrame with predictions
    """
    return predict_attacks(csv_file_path)

