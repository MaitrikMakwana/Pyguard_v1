"""
CICFlowMeter Service - Converts PCAP files to CSV
"""

import glob
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from cicflowmeter.flow_session import FlowSession
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapReader


logger = logging.getLogger(__name__)


def run_cicflowmeter(pcap_file_path, output_folder):
    """
    Run CICFlowMeter on a pcap file to generate CSV

    Args:
        pcap_file_path: Path to the input pcap file
        output_folder: Folder where CSV output will be saved

    Returns:
        Path to the generated CSV file
    """
    print(f"Running CICFlowMeter on: {pcap_file_path}")
    java_error = None

    try:
        return _run_java_cicflowmeter(pcap_file_path, output_folder)
    except Exception as exc:
        java_error = exc
        logger.warning("CICFlowMeter Java execution failed: %s", exc)
        print("CICFlowMeter Java execution failed; attempting Python fallback...")

    try:
        return _run_python_cicflowmeter(pcap_file_path, output_folder)
    except Exception as py_exc:
        logger.warning("Python cicflowmeter fallback failed: %s; trying PyGuard custom extractor...", py_exc)

    try:
        return _run_pyguard_extractor(pcap_file_path, output_folder)
    except Exception as custom_exc:
        message = (
            f"CICFlowMeter failed using Java tool: {java_error}\n"
            f"Python fallback failed: {py_exc}\n"
            f"PyGuard custom extractor failed: {custom_exc}"
        )
        raise Exception(message) from custom_exc


def _run_java_cicflowmeter(pcap_file_path, output_folder):
    """Original CICFlowMeter Java execution."""
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    cicflowmeter_bin = os.path.join(base_dir, "CICFlowmeter", "CICFlowMeter-4.0", "bin", "cfm.bat")

    temp_input_folder = tempfile.mkdtemp()
    pcap_filename = os.path.basename(pcap_file_path)
    temp_pcap_path = os.path.join(temp_input_folder, pcap_filename)

    try:
        shutil.copy2(pcap_file_path, temp_pcap_path)

        os.makedirs(output_folder, exist_ok=True)

        abs_input = os.path.abspath(temp_input_folder)
        abs_output = os.path.abspath(output_folder)
        abs_cfm_bat = os.path.abspath(cicflowmeter_bin)
        cfm_dir = os.path.dirname(abs_cfm_bat)

        print(f"Executing: {abs_cfm_bat} \"{abs_input}\" \"{abs_output}\"")
        result = subprocess.run(
            [abs_cfm_bat, abs_input, abs_output],
            cwd=cfm_dir,
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode != 0:
            raise RuntimeError(result.stderr or result.stdout or "Unknown CICFlowMeter error")

        csv_file = _find_generated_csv(abs_output, pcap_filename)
        print(f"CICFlowMeter generated CSV: {csv_file}")
        return csv_file
    finally:
        try:
            shutil.rmtree(temp_input_folder)
        except Exception:
            pass


def _find_generated_csv(output_folder, pcap_filename):
    csv_patterns = [
        os.path.join(output_folder, f"{os.path.splitext(pcap_filename)[0]}.csv"),
        os.path.join(output_folder, f"{os.path.splitext(pcap_filename)[0]}_Flow.csv"),
        os.path.join(output_folder, "*.csv"),
    ]

    for pattern in csv_patterns:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]

    raise FileNotFoundError(f"No CSV file generated in {output_folder}")


def _run_python_cicflowmeter(pcap_file_path, output_folder):
    """Fallback that uses the Python cicflowmeter package (no Java required)."""
    os.makedirs(output_folder, exist_ok=True)
    output_csv = os.path.join(
        output_folder, f"{Path(pcap_file_path).stem}_flows_python.csv"
    )

    FlowSession.output_mode = "csv"
    FlowSession.output = output_csv
    FlowSession.fields = None
    FlowSession.verbose = False

    session = FlowSession()
    reader = RawPcapReader(os.path.abspath(pcap_file_path))
    packets = 0

    for pkt_data, meta in reader:
        try:
            pkt = Ether(pkt_data)
            # ── Critical fix ──────────────────────────────────────────────────
            # RawPcapReader meta = (sec, usec, wirelen).  Without setting
            # pkt.time, FlowSession cannot compute IAT / flow duration, so all
            # timing features come out as 0 and the model cannot detect attacks.
            pkt.time = meta.sec + meta.usec / 1_000_000
            # ─────────────────────────────────────────────────────────────────
            session.on_packet_received(pkt)
            packets += 1
        except Exception as exc:
            logger.debug("Skipping packet during fallback conversion: %s", exc)
            continue

    session.garbage_collect(None)
    try:
        del session.output_writer
    except AttributeError:
        pass

    if not os.path.exists(output_csv):
        raise FileNotFoundError(
            "Python cicflowmeter fallback did not produce an output CSV."
        )

    print(f"Python cicflowmeter generated CSV: {output_csv} (packets processed: {packets})")
    return output_csv


def _run_pyguard_extractor(pcap_file_path, output_folder):
    """
    Third fallback: PyGuard custom flow extractor.
    Produces a model-ready CSV (all 78 features, correct order) directly from
    the PCAP using real packet timestamps — no Java or cicflowmeter required.
    The output CSV skips the feature_alignment_service step entirely.
    """
    import sys
    pyguard_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    scripts_dir  = os.path.join(pyguard_root, "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)

    from pyguard_flow_extractor import extract_flows_from_pcap

    print(f"Using PyGuard custom flow extractor on: {pcap_file_path}")
    csv_path = extract_flows_from_pcap(pcap_file_path, output_folder)
    return csv_path
