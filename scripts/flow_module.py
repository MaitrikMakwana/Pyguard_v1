import logging
import os
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

class FlowConverter:
	"""Converts PCAP files to flow CSVs using CICFlowMeter CLI.

	Looks for cfm(.bat) under cicflowmeter/CICFlowMeter-4.0/bin.
	"""

	def __init__(self, cic_base: Optional[Path] = None):
		self._bin = (cic_base or (Path(os.getcwd()) / "cicflowmeter" / "CICFlowMeter-4.0" / "bin"))
		self._cli = self._bin / ("cfm.bat" if os.name == "nt" else "cfm")
		self._output_dir = self._bin / "output"
		self._ensure_dirs()

	def _ensure_dirs(self) -> None:
		try:
			self._output_dir.mkdir(parents=True, exist_ok=True)
		except Exception as e:
			logger.error(f"Failed to create CICFlowMeter output directory: {e}")

	def convert(self, pcap_path: str) -> Optional[Path]:
		pcap_file = Path(pcap_path)
		if not self._cli.exists():
			logger.error(f"CICFlowMeter CLI not found: {self._cli}")
			return None
		if not pcap_file.exists():
			logger.error(f"PCAP not found: {pcap_file}")
			return None
		cmd = [str(self._cli), "-r", str(pcap_file), "-o", str(self._output_dir)]
		logger.info(f"Running CICFlowMeter: {' '.join(cmd)}")
		try:
			res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self._bin), timeout=600)
			if res.returncode != 0:
				logger.error(f"CICFlowMeter failed (code {res.returncode}): {res.stderr or res.stdout}")
				return None
			# Find newest CSV
			csvs = list(self._output_dir.glob("*.csv"))
			if not csvs:
				logger.error("CICFlowMeter produced no CSV")
				return None
			latest = max(csvs, key=lambda p: p.stat().st_mtime)
			logger.info(f"Flow CSV ready: {latest}")
			return latest
		except Exception as e:
			logger.error(f"Error running CICFlowMeter: {e}")
			return None 