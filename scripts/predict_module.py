import logging
from pathlib import Path
from typing import Optional

import pandas as pd

from pyguard.core import MLInferenceService

logger = logging.getLogger(__name__)

class Predictor:
	"""Runs ML predictions on a CICFlowMeter CSV using the packaged model.
	"""

	def __init__(self):
		self._service = MLInferenceService()

	def predict_csv(self, csv_path: str) -> Optional[pd.DataFrame]:
		try:
			csv_file = Path(csv_path)
			if not csv_file.exists():
				logger.error(f"CSV not found: {csv_file}")
				return None
			logger.info(f"Predicting for CSV: {csv_file}")
			df = self._service.predict_from_csv(str(csv_file))
			return df
		except Exception as e:
			logger.error(f"Prediction failed: {e}")
			return None 