import logging
import signal
import sys
import threading
import time

from pyguard.core.config import Config

from scripts.capture_module import CaptureService
from scripts.flow_module import FlowConverter
from scripts.predict_module import Predictor

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class Orchestrator:
	"""Coordinates capture → flow generation → prediction."""

	def __init__(self, config: Config):
		self._config = config
		self._capture = CaptureService(config)
		self._flows = FlowConverter()
		self._predictor = Predictor()
		self._stopping = threading.Event()
		self._capture.set_rotation_handler(self._on_pcap_rotated)

	def start(self):
		if not self._capture.start():
			logger.error("Failed to start capture")
			return False
		logger.info("Pipeline started. Press Ctrl+C to stop.")
		return True

	def stop(self):
		self._stopping.set()
		self._capture.stop()
		logger.info("Pipeline stopped")

	def _on_pcap_rotated(self, pcap_path: str):
		logger.info(f"New PCAP ready: {pcap_path}")
		csv_path = self._flows.convert(pcap_path)
		if not csv_path:
			logger.error("Flow conversion failed; skipping prediction")
			return
		pred_df = self._predictor.predict_csv(str(csv_path))
		if pred_df is None:
			logger.error("Prediction failed")
			return
		try:
			label_counts = pred_df['Predicted_Label'].value_counts().to_dict() if 'Predicted_Label' in pred_df.columns else {}
			avg_conf = float(pred_df['Confidence'].mean()) if 'Confidence' in pred_df.columns else 0.0
			logger.info(f"Predictions: {label_counts} | Avg confidence: {avg_conf:.4f}")
		except Exception as e:
			logger.info(f"Predictions completed (summary unavailable): {e}")


def main():
	# Load default config (or extend to parse args)
	cfg = Config()
	orch = Orchestrator(cfg)
	if not orch.start():
		return 1
	
	# Graceful shutdown on Ctrl+C
	def handle_sigint(signum, frame):
		logger.info("Received interrupt, stopping...")
		orch.stop()
		sys.exit(0)
	
	signal.signal(signal.SIGINT, handle_sigint)
	
	# Keep alive loop
	try:
		while True:
			time.sleep(1)
	except KeyboardInterrupt:
		handle_sigint(None, None)
	return 0

if __name__ == "__main__":
	sys.exit(main()) 