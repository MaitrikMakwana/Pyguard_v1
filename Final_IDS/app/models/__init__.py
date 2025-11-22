"""
Model components for attack detection
"""

from .gcn_model import GCN, load_model_and_preprocessors, predict_attacks

__all__ = ['GCN', 'load_model_and_preprocessors', 'predict_attacks']

