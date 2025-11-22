import os
import threading
from typing import Optional

import pandas as pd


class MLInferenceService:
	"""Singleton-like service for running ML predictions using Model/predict.py.

	Loads the model and preprocessors once and reuses them for subsequent predictions.
	"""

	_instance_lock = threading.Lock()
	_instance: Optional["MLInferenceService"] = None

	def __new__(cls, *args, **kwargs):
		with cls._instance_lock:
			if cls._instance is None:
				cls._instance = super().__new__(cls)
		return cls._instance

	def __init__(self):
		if getattr(self, "_initialized", False):
			return
		self._initialized = True
		self._model = None
		self._scaler = None
		self._label_encoder = None
		self._metadata = None
		self._device = None
		self._predict_module = None

	def _ensure_loaded(self):
		"""Ensure the model and preprocessors are loaded from Model/predict.py."""
		if self._model is not None:
			return
		# Dynamically import Model/predict.py
		model_dir = os.path.join(os.getcwd(), "Model")
		if model_dir not in os.sys.path:
			os.sys.path.append(model_dir)
		import importlib
		self._predict_module = importlib.import_module("predict")
		(
			self._model,
			self._scaler,
			self._label_encoder,
			self._metadata,
			self._device,
		) = self._predict_module.load_model_and_preprocessors()

	def predict_from_csv(self, csv_path: str) -> pd.DataFrame:
		"""Run predictions on a CSV and return a DataFrame with results."""
		self._ensure_loaded()
		return self._predict_module.predict_attacks(csv_path) 