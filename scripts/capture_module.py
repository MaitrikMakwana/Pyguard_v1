import logging
import threading
from pathlib import Path
from typing import Callable, Optional

from pyguard.core.config import Config
from pyguard.core.packet_capture import PacketCapture

logger = logging.getLogger(__name__)

class CaptureService:
	"""Thin wrapper around PacketCapture that exposes PCAP rotation callbacks.

	Use `on_pcap_rotated` to receive a path for every finalized PCAP file.
	"""

	def __init__(self, config: Config):
		self._config = config
		self._packet_capture = PacketCapture(self._config)
		self._packet_capture.on_pcap_rotated = self._on_pcap_rotated_internal
		self._user_rotation_handler: Optional[Callable[[str], None]] = None
		self._running = False
		self._lock = threading.Lock()

	def set_rotation_handler(self, handler: Callable[[str], None]) -> None:
		self._user_rotation_handler = handler

	def start(self) -> bool:
		with self._lock:
			if self._running:
				logger.warning("CaptureService already running")
				return True
			logger.info("Starting CaptureService")
			ok = self._packet_capture.start()
			self._running = ok
			return ok

	def stop(self) -> None:
		with self._lock:
			if not self._running:
				return
			logger.info("Stopping CaptureService")
			self._packet_capture.stop()
			self._running = False

	def _on_pcap_rotated_internal(self, pcap_path: str) -> None:
		try:
			pcap_file = Path(pcap_path)
			logger.info(f"CaptureService rotated PCAP: {pcap_file}")
			if self._user_rotation_handler:
				self._user_rotation_handler(str(pcap_file))
		except Exception as e:
			logger.error(f"Rotation handler failed: {e}") 