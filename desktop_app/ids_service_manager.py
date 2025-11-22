"""
IDS Service Manager - Manages communication with the Final_IDS microservice.
"""

import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover - handled at runtime
    requests = None  # type: ignore

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Locate the Final_IDS package so we can run the pipeline locally if needed.
# --------------------------------------------------------------------------- #
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

FINAL_IDS_PATH = REPO_ROOT / "Final_IDS"
process_pcap_to_attacks = None  # type: ignore
_LOCAL_PIPELINE_AVAILABLE = False
_LOCAL_PIPELINE_ERROR: Optional[str] = None

if FINAL_IDS_PATH.exists():
    try:
        from Final_IDS.app.main import process_pcap_to_attacks  # type: ignore

        _LOCAL_PIPELINE_AVAILABLE = True
        logger.info("Local Final_IDS pipeline detected – IDS analysis can run without HTTP service.")
    except Exception as exc:  # pragma: no cover - import-time protection
        _LOCAL_PIPELINE_ERROR = f"Failed to import Final_IDS pipeline: {exc}"
        logger.warning(_LOCAL_PIPELINE_ERROR)
else:
    _LOCAL_PIPELINE_ERROR = f"Final_IDS directory not found at {FINAL_IDS_PATH}"
    logger.debug(_LOCAL_PIPELINE_ERROR)


class IDSServiceError(RuntimeError):
    """Raised when communication with the IDS service fails."""


class IDSServiceManager:
    """Manages communication with the Final_IDS microservice."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 5000,
        timeout: int = 300,
        prefer_remote: bool = True,
    ) -> None:
        self.base_url = f"http://{host}:{port}"
        self.timeout = timeout  # Allow longer processing time for large PCAP files
        self.last_error: Optional[str] = None
        self.prefer_remote = prefer_remote
        self.active_backend: Optional[str] = None
        self.local_pipeline_available = _LOCAL_PIPELINE_AVAILABLE
        self.local_pipeline_error = _LOCAL_PIPELINE_ERROR

    # --------------------------------------------------------------------- #
    # Service health
    # --------------------------------------------------------------------- #
    def check_health(self) -> bool:
        """Return True when the IDS service reports a healthy status."""
        self.last_error = None

        remote_checked = False
        if self.has_remote_backend:
            remote_checked = True
            try:
                response = requests.get(f"{self.base_url}/health", timeout=10)  # type: ignore[arg-type]
            except requests.RequestException as exc:  # pragma: no cover - network dependent
                self.last_error = str(exc)
                logger.error("IDS HTTP health check failed: %s", exc)
            else:
                if response.status_code == 200:
                    try:
                        payload = response.json()
                    except ValueError:
                        payload = {}

                    status = str(payload.get("status", "")).lower()
                    if status in {"healthy", "ok", "success"}:
                        self.active_backend = "remote"
                        return True

                    message = str(payload.get("message") or "IDS service reported an unhealthy status.")
                    self.last_error = message
                    logger.warning("IDS health check reported unhealthy status: %s", message)
                else:
                    self.last_error = f"Health endpoint returned HTTP {response.status_code}"
                    logger.error(self.last_error)

        if self.supports_local_analysis:
            if not remote_checked and not self.has_remote_backend and self.local_pipeline_error:
                logger.info(
                    "Using built-in IDS pipeline because remote service is unavailable: %s",
                    self.local_pipeline_error,
                )
            self.active_backend = "local"
            self.last_error = None
            return True

        if not remote_checked and not self.has_remote_backend:
            self.last_error = "Neither HTTP service nor local IDS pipeline is available."
        return False

    # --------------------------------------------------------------------- #
    # Analysis
    # --------------------------------------------------------------------- #
    def analyze_pcap(self, pcap_path: str) -> Dict:
        """
        Send a PCAP file to the IDS service for analysis.

        :param pcap_path: Absolute path to the PCAP file on disk.
        :raises IDSServiceError: If the request fails or the service returns an error payload.
        :return: Parsed JSON response from the IDS service.
        """
        if not os.path.exists(pcap_path):
            raise IDSServiceError(f"PCAP file does not exist: {pcap_path}")

        errors: List[str] = []

        should_try_remote = self.prefer_remote and self.has_remote_backend
        if should_try_remote:
            try:
                return self._analyze_remote(pcap_path)
            except IDSServiceError as exc:
                errors.append(str(exc))
                logger.warning("Remote IDS service failed; attempting local pipeline if available.")

        if self.supports_local_analysis:
            try:
                return self._analyze_local(pcap_path)
            except IDSServiceError as exc:
                errors.append(str(exc))

        if not should_try_remote and self.has_remote_backend:
            # Remote backend is available but not preferred; attempt now.
            try:
                return self._analyze_remote(pcap_path)
            except IDSServiceError as exc:
                errors.append(str(exc))

        if errors:
            raise IDSServiceError(" | ".join(errors))

        raise IDSServiceError("No IDS analysis backend is available. Install 'requests' or ensure Final_IDS is present.")

    # --------------------------------------------------------------------- #
    # Result helpers
    # --------------------------------------------------------------------- #
    def get_attack_summary(self, results: Dict) -> Dict:
        """Extract a normalized summary from the raw IDS API response."""
        if not results:
            return {}

        attack_summary = dict(results.get("attack_summary") or {})
        benign_flows = results.get("benign_flows", attack_summary.get("BENIGN", 0))
        attack_flows = results.get(
            "attack_flows",
            sum(count for label, count in attack_summary.items() if label != "BENIGN"),
        )

        total_flows = results.get("total_flows")
        if total_flows is None:
            total_flows = benign_flows + attack_flows

        detailed_results = list(results.get("detailed_results") or [])

        summary = {
            "status": results.get("status", "unknown"),
            "total_flows": total_flows,
            "attack_flows": attack_flows,
            "benign_flows": benign_flows,
            "average_confidence": float(results.get("average_confidence", 0.0)),
            "attack_summary": attack_summary,
            "top_attacks": list(results.get("top_attacks") or []),
            "detailed_results": detailed_results,
        }

        # Derive a simple completion flag for the UI
        summary["status_label"] = results.get("status", "unknown").capitalize()

        return summary

    def get_attack_types(self, results: Dict) -> List[str]:
        """Return the list of attack labels (excluding BENIGN) present in the results."""
        summary = self.get_attack_summary(results)
        attack_summary = summary.get("attack_summary", {})
        return [
            attack
            for attack, count in attack_summary.items()
            if attack.upper() != "BENIGN" and count
        ]

    def get_attack_distribution(self, results: Dict) -> Dict[str, int]:
        """Return the attack distribution excluding BENIGN traffic."""
        summary = self.get_attack_summary(results)
        attack_summary = summary.get("attack_summary", {})
        return {label: count for label, count in attack_summary.items() if label != "BENIGN"}

    def prepare_results_payload(self, results: Dict) -> Dict:
        """Return a structure containing both raw results and the normalized summary."""
        return {
            "raw": results,
            "summary": self.get_attack_summary(results),
        }

    # ------------------------------------------------------------------ #
    # Backend helpers
    # ------------------------------------------------------------------ #
    @property
    def has_remote_backend(self) -> bool:
        """Return True if HTTP communication is possible."""
        return requests is not None

    @property
    def supports_local_analysis(self) -> bool:
        """Return True if the Final_IDS pipeline is importable."""
        return self.local_pipeline_available

    @property
    def has_any_backend(self) -> bool:
        """Return True if either HTTP or local analysis is available."""
        return self.has_remote_backend or self.supports_local_analysis

    def _analyze_remote(self, pcap_path: str) -> Dict:
        if not self.has_remote_backend:
            raise IDSServiceError("Python 'requests' package is not installed.")

        try:
            with open(pcap_path, "rb") as handle:
                response = requests.post(  # type: ignore[call-arg]
                    f"{self.base_url}/analyze",
                    files={"file": handle},
                    timeout=self.timeout,
                )
        except requests.RequestException as exc:  # pragma: no cover - network dependent
            raise IDSServiceError(f"Failed to contact IDS service: {exc}") from exc

        if response.status_code != 200:
            snippet = response.text[:500]
            raise IDSServiceError(f"IDS analysis failed with HTTP {response.status_code}: {snippet}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise IDSServiceError(f"IDS response was not valid JSON: {exc}") from exc

        if payload.get("status") != "success":
            message = payload.get("message") or payload.get("error") or "IDS reported failure status."
            raise IDSServiceError(str(message))

        self.active_backend = "remote"
        return payload

    def _analyze_local(self, pcap_path: str) -> Dict:
        if not self.supports_local_analysis or process_pcap_to_attacks is None:
            raise IDSServiceError(self.local_pipeline_error or "Local IDS pipeline is unavailable.")

        try:
            results = process_pcap_to_attacks(pcap_path)
        except Exception as exc:  # pragma: no cover - runtime safety
            raise IDSServiceError(f"Local IDS pipeline failed: {exc}") from exc

        if not isinstance(results, dict):
            raise IDSServiceError("Local IDS pipeline returned an unexpected response.")

        if results.get("status") != "success":
            message = results.get("message") or results.get("error") or "Local IDS pipeline reported failure."
            raise IDSServiceError(str(message))

        self.active_backend = "local"
        return results

