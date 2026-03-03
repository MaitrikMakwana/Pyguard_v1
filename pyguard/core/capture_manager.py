"""
Capture Manager module for coordinating packet capture and processing
with support for multi-interface capture and advanced features
"""

import os
import time
import logging
import threading
import queue
import asyncio
from datetime import datetime
from pathlib import Path
import subprocess

from pyguard.core.packet_capture import PacketCapture
from pyguard.core.packet_processor import PacketProcessor
from pyguard.storage.database_storage import DatabaseStorage
from pyguard.storage.csv_storage import CSVStorage
from pyguard.storage.json_storage import JSONStorage
from pyguard.core import MLInferenceService

logger = logging.getLogger(__name__)

class CaptureManager:
	"""Manages packet capture and processing workflow with multi-interface support"""
	
	def __init__(self, config):
		"""Initialize capture manager with configuration"""
		self.config = config
		self.output_dir = Path(config.output_dir)
		os.makedirs(self.output_dir, exist_ok=True)
		
		# Check for multi-interface configuration
		self.multi_interface = len(config.interfaces) > 0
		
		if self.multi_interface:
			# Create packet capture instances for each interface
			self.packet_captures = {}
			for interface in config.interfaces:
				# Create a copy of the config with the specific interface
				interface_config = self._create_interface_config(config, interface)
				self.packet_captures[interface] = PacketCapture(interface_config)
		else:
			# Create a single packet capture instance
			self.packet_captures = {config.interface: PacketCapture(config)}
		
		# Attach PCAP rotation handlers
		for pc in self.packet_captures.values():
			try:
				pc.on_pcap_rotated = self._handle_pcap_rotated
			except Exception as e:
				logger.error(f"Failed to attach rotation handler: {e}")
		
		# Create packet processor instance
		self.packet_processor = PacketProcessor(config)
		
		# Create storage instances
		self.db_storage = None
		if config.database["enabled"]:
			self.db_storage = DatabaseStorage(config)
		
		self.csv_storage = None
		if config.csv_export["enabled"]:
			self.csv_storage = CSVStorage(config)
		
		# ML inference service (lazy)
		self._ml_service = None
		
		# Derived paths
		self.cic_bin = Path(os.getcwd()) / "cicflowmeter" / "CICFlowMeter-4.0" / "bin"
		self.cic_cli = self.cic_bin / "cfm.bat" if os.name == "nt" else self.cic_bin / "cfm"
		self.cic_output_dir = self.cic_bin / "output"
		
		# Runtime state
		self.running = False
		self.num_processing_threads = config.capture.get("processing_threads", 2)
		self.processing_threads = []
		self.stats_thread = None
		self.stats = {
			"packets_processed": 0,
			"packets_stored_db": 0,
			"packets_stored_csv": 0,
			"processing_errors": 0,
			"start_time": None,
			"last_update_time": None,
		}

		# Live prediction summary state
		self._pred_summary_lock = threading.Lock()
		self._latest_pred_summary = {
			"total": 0,
			"avg_confidence": 0.0,
			"label_counts": {},
			"last_csv": None,
			"last_pcap": None,
			"last_updated": None,
		}
		
	@property
	def packet_capture(self):
		"""Return the primary PacketCapture instance (first interface)."""
		return next(iter(self.packet_captures.values()))

	def _create_interface_config(self, base_config, interface):
		"""Create a config copy with a specific interface"""
		# This is a simplified approach - in a real implementation,
		# you would create a proper deep copy of the config object
		import copy
		interface_config = copy.deepcopy(base_config)
		interface_config.interface = interface
		return interface_config
	
	def _get_ml_service(self) -> MLInferenceService:
		if self._ml_service is None:
			self._ml_service = MLInferenceService()
		return self._ml_service
	
	def get_latest_prediction_summary(self):
		"""Thread-safe getter for the latest prediction summary."""
		with self._pred_summary_lock:
			return dict(self._latest_pred_summary)
	
	def _handle_pcap_rotated(self, pcap_path: str):
		"""Background task: run CICFlowMeter CLI for rotated PCAP, then ML prediction.
		Saves CSV in CICFlowMeter output and predictions next to the PCAP.
		Also updates in-memory summary for UI polling.
		"""
		def worker():
			try:
				pcap_file = Path(pcap_path)
				logger.info(f"Processing rotated PCAP via CICFlowMeter: {pcap_file}")
				# Ensure CIC output directory exists
				os.makedirs(self.cic_output_dir, exist_ok=True)
				# Run CICFlowMeter CLI on this PCAP
				if not self.cic_cli.exists():
					logger.error("CICFlowMeter CLI not found. Skipping flow conversion.")
					return
				# Command: cfm -r <pcap> -o <outdir>
				cmd = [str(self.cic_cli), "-r", str(pcap_file), "-o", str(self.cic_output_dir)]
				logger.info(f"Running: {' '.join(cmd)}")
				try:
					result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.cic_bin), timeout=600)
					if result.returncode != 0:
						logger.error(f"CICFlowMeter failed: {result.stderr}")
						return
					logger.info("CICFlowMeter completed")
				except Exception as e:
					logger.error(f"Error running CICFlowMeter: {e}")
					return
				# Find the newest CSV generated by CICFlowMeter
				csv_files = list(self.cic_output_dir.glob("*.csv"))
				if not csv_files:
					logger.error("No CSV generated by CICFlowMeter")
					return
				latest_csv = max(csv_files, key=lambda p: p.stat().st_mtime)
				logger.info(f"Latest flow CSV: {latest_csv}")
				# Run ML predictions and save alongside PCAP
				pred_df = self._get_ml_service().predict_from_csv(str(latest_csv))
				pred_out = pcap_file.with_suffix("")
				pred_csv = pred_out.parent / f"{pred_out.name}_predictions.csv"
				pred_df.to_csv(pred_csv, index=False)
				logger.info(f"Saved predictions: {pred_csv}")
				# Update summary for UI
				try:
					label_counts = pred_df["Predicted_Label"].value_counts().to_dict() if "Predicted_Label" in pred_df.columns else {}
					total = int(sum(label_counts.values()))
					avg_conf = float(pred_df["Confidence"].mean()) if "Confidence" in pred_df.columns and total > 0 else 0.0
					with self._pred_summary_lock:
						self._latest_pred_summary = {
							"total": total,
							"avg_confidence": avg_conf,
							"label_counts": label_counts,
							"last_csv": str(latest_csv),
							"last_pcap": str(pcap_file),
							"last_updated": time.time(),
						}
				except Exception as se:
					logger.error(f"Failed to compute prediction summary: {se}")
			except Exception as e:
				logger.error(f"Error in PCAP rotated handler: {e}")
		
		threading.Thread(target=worker, daemon=True).start()
	
	def start(self):
		"""Start capture and processing"""
		if self.running:
			logger.warning("Capture manager already running")
			return False
		
		try:
			logger.info("Starting capture manager")
			
			# Initialize storage
			if self.db_storage:
				self.db_storage.connect()
				self.db_storage.initialize_schema()
			
			if self.csv_storage:
				self.csv_storage.initialize()
			
			# Start all packet capture instances
			for iface, pc in self.packet_captures.items():
				if not pc.start():
					logger.error(f"Failed to start packet capture on interface: {iface}")
					return False
			
			# Start processing threads
			self.running = True
			self.stats["start_time"] = time.time()
			self.stats["last_update_time"] = time.time()
			self.processing_threads = []
			
			for i in range(self.num_processing_threads):
				thread = threading.Thread(
					target=self._processing_thread,
					name=f"ProcessingThread-{i}",
					daemon=True
				)
				thread.start()
				self.processing_threads.append(thread)
			
			logger.info(f"Started {self.num_processing_threads} processing threads")
			
			# Start statistics thread
			self.stats_thread = threading.Thread(
				target=self._stats_thread,
				name="StatsThread",
				daemon=True
			)
			self.stats_thread.start()
			
			return True
		
		except Exception as e:
			logger.error(f"Error starting capture manager: {e}")
			self.running = False
			return False
	
	def stop(self):
		"""Stop capture and processing"""
		if not self.running:
			logger.warning("Capture manager not running")
			return
		
		logger.info("Stopping capture manager")
		self.running = False
		
		# Stop all packet capture instances
		for pc in self.packet_captures.values():
			pc.stop()
		
		# Wait for processing threads to finish
		for thread in self.processing_threads:
			thread.join(timeout=5)
		
		# Close storage connections
		if self.db_storage:
			self.db_storage.commit()
			self.db_storage.close()
		
		if self.csv_storage:
			self.csv_storage.close()
		
		# Log final statistics
		self._log_statistics()
		
		logger.info("Capture manager stopped")
	
	def _processing_thread(self):
		"""Processing thread function"""
		logger.info(f"Processing thread {threading.current_thread().name} started")
		
		batch_size = self.config.capture["batch_size"]
		batch_items = []
		last_commit_time = time.time()
		commit_interval = self.config.database["commit_interval"]
		
		while self.running or not self.packet_capture.packet_queue.empty():
			try:
				# Get packet from queue with timeout (use primary capture instance)
				packet_data = self.packet_capture.get_packet(timeout=0.1)
				if not packet_data:
					# Check if it's time to commit the current batch
					if batch_items and (time.time() - last_commit_time) > commit_interval:
						self._store_batch(batch_items)
						batch_items = []
						last_commit_time = time.time()
					continue
				
				header, packet = packet_data
				
				# Process packet to extract metadata
				metadata = self.packet_processor.process_packet(header, packet)
				
				# Add to batch
				batch_items.append(metadata)
				
				# Mark packet as processed
				self.packet_capture.task_done()
				
				# Update statistics
				self.stats["packets_processed"] += 1
				
				# Store batch if it reaches the batch size
				if len(batch_items) >= batch_size:
					self._store_batch(batch_items)
					batch_items = []
					last_commit_time = time.time()
			
			except Exception as e:
				logger.error(f"Error in processing thread: {e}")
				self.stats["processing_errors"] += 1
				time.sleep(0.1)  # Avoid tight error loop
		
		# Store any remaining items in the batch
		if batch_items:
			self._store_batch(batch_items)
		
		logger.info(f"Processing thread {threading.current_thread().name} stopped")
	
	def _store_batch(self, batch_items):
		"""Store a batch of processed packets"""
		if not batch_items:
			return
		
		# Store in database if enabled
		if self.db_storage:
			try:
				self.db_storage.store_batch(batch_items)
				self.stats["packets_stored_db"] += len(batch_items)
			except Exception as e:
				logger.error(f"Error storing batch in database: {e}")
		
		# Store in CSV if enabled
		if self.csv_storage:
			try:
				self.csv_storage.store_batch(batch_items)
				self.stats["packets_stored_csv"] += len(batch_items)
			except Exception as e:
				logger.error(f"Error storing batch in CSV: {e}")
	
	def _stats_thread(self):
		"""Statistics thread function"""
		logger.info("Statistics thread started")
		
		while self.running:
			try:
				# Sleep for a while
				time.sleep(10)
				
				# Log statistics
				self._log_statistics()
			
			except Exception as e:
				logger.error(f"Error in statistics thread: {e}")
				time.sleep(1)  # Avoid tight error loop
		
		logger.info("Statistics thread stopped")
	
	def _log_statistics(self):
		"""Log capture and processing statistics"""
		current_time = time.time()
		elapsed = current_time - self.stats["start_time"]
		interval = current_time - self.stats["last_update_time"]
		self.stats["last_update_time"] = current_time
		
		# Aggregate capture statistics across all interfaces
		capture_stats = {}
		for pc in self.packet_captures.values():
			for k, v in pc.get_stats().items():
				if isinstance(v, (int, float)):
					capture_stats[k] = capture_stats.get(k, 0) + v
				else:
					capture_stats.setdefault(k, v)
		
		# Calculate rates
		packets_per_second = self.stats["packets_processed"] / elapsed if elapsed > 0 else 0
		interval_packets = self.stats["packets_processed"] - self.stats.get("last_packets_processed", 0)
		interval_rate = interval_packets / interval if interval > 0 else 0
		self.stats["last_packets_processed"] = self.stats["packets_processed"]
		
		# Log statistics
		logger.info(
			f"Statistics: Processed={self.stats['packets_processed']} "
			f"(avg={packets_per_second:.1f}/s, current={interval_rate:.1f}/s), "
			f"DB={self.stats['packets_stored_db']}, CSV={self.stats['packets_stored_csv']}, "
			f"Errors={self.stats['processing_errors']}, "
			f"Queue={capture_stats.get('queue_size', 'N/A')}, "
			f"Dropped={capture_stats.get('dropped', 'N/A')}"
		)
	
	def get_statistics(self):
		"""Get current statistics"""
		stats = self.stats.copy()
		
		# Aggregate capture statistics across all interfaces
		for pc in self.packet_captures.values():
			for k, v in pc.get_stats().items():
				if isinstance(v, (int, float)):
					stats[k] = stats.get(k, 0) + v
				else:
					stats.setdefault(k, v)
		
		# Calculate elapsed time and rates
		current_time = time.time()
		if stats["start_time"]:
			elapsed = current_time - stats["start_time"]
			stats["elapsed_time"] = elapsed
			stats["packets_per_second"] = stats["packets_processed"] / elapsed if elapsed > 0 else 0
		
		return stats