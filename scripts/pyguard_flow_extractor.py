"""
PyGuard Custom Flow Extractor
==============================
Converts raw PCAP files into network flow CSVs with all 78 features expected
by the GCN model — without requiring Java or the Python cicflowmeter library.

Usage (standalone):
    python scripts/pyguard_flow_extractor.py <input.pcap> <output.csv>

Usage (as a library):
    from scripts.pyguard_flow_extractor import extract_flows_from_pcap
    csv_path = extract_flows_from_pcap("capture.pcap", "/tmp/out")
"""

import os
import sys
import math
import numpy as np
import pandas as pd
from collections import defaultdict
from pathlib import Path

try:
    from scapy.utils import RawPcapReader
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
except ImportError:
    raise ImportError("scapy is required: pip install scapy")

# ──────────────────────────────────────────────────────────────────────────────
# Constants  (match CICFlowMeter defaults)
# ──────────────────────────────────────────────────────────────────────────────
FLOW_TIMEOUT_S   = 120          # seconds of inactivity → export flow
ACTIVITY_TIMEOUT = 5_000_000    # µs between activity periods (5 s)

# Model feature column order (must match model_metadata.pkl exactly)
MODEL_COLUMNS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max",
    "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max",
    "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
    "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length",
    "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count",
    "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
    "Subflow Bwd Bytes", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "Active Mean", "Active Std",
    "Active Max", "Active Min", "Idle Mean", "Idle Std",
    "Idle Max", "Idle Min", "Fwd Header Length.1",
]


# ──────────────────────────────────────────────────────────────────────────────
# Helper — safe statistics on a list of values
# ──────────────────────────────────────────────────────────────────────────────
def _safe(lst, fn, default=0.0):
    try:
        return float(fn(lst)) if lst else default
    except Exception:
        return default

def _iat_stats(ts_list):
    """Compute IAT statistics (µs) from a sorted list of timestamps (float s)."""
    if len(ts_list) < 2:
        return 0.0, 0.0, 0.0, 0.0, 0.0          # tot, mean, std, max, min
    iats = [(ts_list[i] - ts_list[i-1]) * 1e6 for i in range(1, len(ts_list))]
    total = sum(iats)
    mean  = total / len(iats)
    std   = math.sqrt(sum((x - mean) ** 2 for x in iats) / len(iats))
    return total, mean, std, max(iats), min(iats)


# ──────────────────────────────────────────────────────────────────────────────
# Active / Idle tracking
# ──────────────────────────────────────────────────────────────────────────────
def _active_idle(all_ts, timeout_us=ACTIVITY_TIMEOUT):
    """Calculate Active/Idle period statistics from packet timestamps."""
    active, idle = [], []
    if len(all_ts) < 2:
        return [0.0], [0.0], [0.0], [0.0], [0.0], [0.0], [0.0], [0.0]

    period_start = all_ts[0]
    last_ts      = all_ts[0]

    for ts in all_ts[1:]:
        gap = (ts - last_ts) * 1e6           # in µs
        if gap > timeout_us:
            active.append((last_ts - period_start) * 1e6)
            idle.append(gap)
            period_start = ts
        last_ts = ts

    active.append((last_ts - period_start) * 1e6)

    def _stats(lst):
        if not lst:
            return [0.0, 0.0, 0.0, 0.0]
        mean = sum(lst) / len(lst)
        std  = math.sqrt(sum((x - mean)**2 for x in lst) / len(lst))
        return [mean, std, max(lst), min(lst)]

    a = _stats(active)
    i = _stats(idle)
    return a[0], a[1], a[2], a[3], i[0], i[1], i[2], i[3]


# ──────────────────────────────────────────────────────────────────────────────
# Per-packet info extraction
# ──────────────────────────────────────────────────────────────────────────────
def _parse_packet(pkt, ts):
    """
    Returns a flat dict of per-packet fields needed for flow computation,
    or None if the packet is not IP/TCP/UDP (ARP, etc.).
    """
    if not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
        return None

    ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]

    # Protocol number
    proto   = getattr(ip, "proto", getattr(ip, "nh", 0))
    src_ip  = str(ip.src)
    dst_ip  = str(ip.dst)

    src_port = dst_port = 0
    tcp_flags = 0
    win_size  = 0
    hdr_len   = 0

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        src_port  = tcp.sport
        dst_port  = tcp.dport
        tcp_flags = int(tcp.flags)
        win_size  = tcp.window
        hdr_len   = tcp.dataofs * 4 if tcp.dataofs else 20
        proto     = 6
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        src_port = udp.sport
        dst_port = udp.dport
        hdr_len  = 8
        proto    = 17
    elif pkt.haslayer(ICMP):
        proto  = 1
        hdr_len = 8

    ip_hdr_len = (ip.ihl * 4) if hasattr(ip, "ihl") and ip.ihl else 20
    pkt_len    = len(pkt)

    return {
        "ts":        ts,
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "src_port":  src_port,
        "dst_port":  dst_port,
        "proto":     proto,
        "pkt_len":   pkt_len,
        "ip_hdr":    ip_hdr_len,
        "tcp_hdr":   hdr_len,
        "total_hdr": ip_hdr_len + hdr_len,
        "win":       win_size,
        # TCP flags
        "fin": 1 if tcp_flags & 0x01 else 0,
        "syn": 1 if tcp_flags & 0x02 else 0,
        "rst": 1 if tcp_flags & 0x04 else 0,
        "psh": 1 if tcp_flags & 0x08 else 0,
        "ack": 1 if tcp_flags & 0x10 else 0,
        "urg": 1 if tcp_flags & 0x20 else 0,
        "ece": 1 if tcp_flags & 0x40 else 0,
        "cwr": 1 if tcp_flags & 0x80 else 0,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Flow class
# ──────────────────────────────────────────────────────────────────────────────
class _Flow:
    def __init__(self, first_pkt):
        self.fwd_ip   = first_pkt["src_ip"]
        self.fwd_port = first_pkt["src_port"]
        self.bwd_ip   = first_pkt["dst_ip"]
        self.bwd_port = first_pkt["dst_port"]
        self.proto    = first_pkt["proto"]
        self.dst_port = first_pkt["dst_port"]

        self.fwd_pkts  = []    # list of pkt dicts
        self.bwd_pkts  = []
        self.all_ts    = []

        self.last_seen = first_pkt["ts"]
        self._add(first_pkt)

    def _is_fwd(self, p):
        return p["src_ip"] == self.fwd_ip and p["src_port"] == self.fwd_port

    def add(self, pkt):
        self._add(pkt)
        self.last_seen = pkt["ts"]

    def _add(self, p):
        self.all_ts.append(p["ts"])
        if self._is_fwd(p):
            self.fwd_pkts.append(p)
        else:
            self.bwd_pkts.append(p)

    def is_expired(self, ts):
        return (ts - self.last_seen) > FLOW_TIMEOUT_S

    def should_close(self, pkt):
        """Close on RST or bidirectional FIN."""
        return pkt["rst"] == 1

    def to_features(self):
        """Build the 78-feature dict for this flow."""
        f, b, all_ts = self.fwd_pkts, self.bwd_pkts, sorted(self.all_ts)
        if not all_ts:
            return None

        dur_us = (all_ts[-1] - all_ts[0]) * 1e6   # microseconds

        # ── Packet lengths ───────────────────────────────────────────────────
        fwd_lens = [p["pkt_len"] for p in f]
        bwd_lens = [p["pkt_len"] for p in b]
        all_lens = fwd_lens + bwd_lens

        fwd_hdr  = sum(p["total_hdr"] for p in f)
        bwd_hdr  = sum(p["total_hdr"] for p in b)

        # ── Rates ────────────────────────────────────────────────────────────
        # For single-packet flows dur_us=0 — rates are meaningless; set to 0
        # to avoid the 1/1e-9 = 1 billion inflation that confuses the model.
        has_duration = dur_us > 0
        dur_s    = dur_us / 1e6 if has_duration else 0.0
        tot_bytes = sum(all_lens)
        tot_pkts  = len(all_ts)

        # ── IAT ──────────────────────────────────────────────────────────────
        flow_iat_tot, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = \
            _iat_stats(all_ts)
        fwd_ts  = sorted(p["ts"] for p in f)
        bwd_ts  = sorted(p["ts"] for p in b)
        fwd_iat_tot, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = \
            _iat_stats(fwd_ts)
        bwd_iat_tot, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = \
            _iat_stats(bwd_ts)

        # ── Flags ────────────────────────────────────────────────────────────
        def flag_sum(pkts, flag): return sum(p[flag] for p in pkts)

        fwd_psh = flag_sum(f, "psh")
        bwd_psh = flag_sum(b, "psh")
        fwd_urg = flag_sum(f, "urg")
        bwd_urg = flag_sum(b, "urg")

        all_pkts = f + b
        fin_cnt  = flag_sum(all_pkts, "fin")
        syn_cnt  = flag_sum(all_pkts, "syn")
        rst_cnt  = flag_sum(all_pkts, "rst")
        psh_cnt  = flag_sum(all_pkts, "psh")
        ack_cnt  = flag_sum(all_pkts, "ack")
        urg_cnt  = flag_sum(all_pkts, "urg")
        cwe_cnt  = flag_sum(all_pkts, "cwr")
        ece_cnt  = flag_sum(all_pkts, "ece")

        # ── Init window ──────────────────────────────────────────────────────
        init_fwd_win = f[0]["win"] if f else 0
        init_bwd_win = b[0]["win"] if b else 0

        # ── act_data_pkt_fwd: fwd pkts with payload ─────────────────────────
        act_fwd = sum(1 for p in f if p["pkt_len"] > p["total_hdr"])

        # ── min_seg_size_forward ─────────────────────────────────────────────
        min_seg_fwd = _safe([p["tcp_hdr"] for p in f], min)

        # ── Active / Idle ────────────────────────────────────────────────────
        act_mean, act_std, act_max, act_min, idle_mean, idle_std, idle_max, idle_min = \
            _active_idle(all_ts)

        # ── Down/Up ratio ────────────────────────────────────────────────────
        fwd_tot_len = sum(fwd_lens)
        bwd_tot_len = sum(bwd_lens)
        down_up = bwd_tot_len / fwd_tot_len if fwd_tot_len > 0 else 0

        pkt_mean = _safe(all_lens, lambda x: sum(x)/len(x))
        pkt_var  = _safe(all_lens, lambda x: sum((v - sum(x)/len(x))**2/len(x) for v in x))
        pkt_std  = math.sqrt(pkt_var) if pkt_var >= 0 else 0

        fwd_mean = _safe(fwd_lens, lambda x: sum(x)/len(x))
        bwd_mean = _safe(bwd_lens, lambda x: sum(x)/len(x))

        return {
            "Destination Port":            self.dst_port,
            "Flow Duration":               dur_us,
            "Total Fwd Packets":           len(f),
            "Total Backward Packets":      len(b),
            "Total Length of Fwd Packets": fwd_tot_len,
            "Total Length of Bwd Packets": bwd_tot_len,
            "Fwd Packet Length Max":       _safe(fwd_lens, max),
            "Fwd Packet Length Min":       _safe(fwd_lens, min),
            "Fwd Packet Length Mean":      fwd_mean,
            "Fwd Packet Length Std":       _safe(fwd_lens, lambda x: math.sqrt(sum((v-fwd_mean)**2 for v in x)/len(x)) if len(x)>1 else 0),
            "Bwd Packet Length Max":       _safe(bwd_lens, max),
            "Bwd Packet Length Min":       _safe(bwd_lens, min),
            "Bwd Packet Length Mean":      bwd_mean,
            "Bwd Packet Length Std":       _safe(bwd_lens, lambda x: math.sqrt(sum((v-bwd_mean)**2 for v in x)/len(x)) if len(x)>1 else 0),
            "Flow Bytes/s":                (tot_bytes / dur_s) if dur_s > 0 else 0.0,
            "Flow Packets/s":              (tot_pkts  / dur_s) if dur_s > 0 else 0.0,
            "Flow IAT Mean":               flow_iat_mean,
            "Flow IAT Std":                flow_iat_std,
            "Flow IAT Max":                flow_iat_max,
            "Flow IAT Min":                flow_iat_min,
            "Fwd IAT Total":               fwd_iat_tot,
            "Fwd IAT Mean":                fwd_iat_mean,
            "Fwd IAT Std":                 fwd_iat_std,
            "Fwd IAT Max":                 fwd_iat_max,
            "Fwd IAT Min":                 fwd_iat_min,
            "Bwd IAT Total":               bwd_iat_tot,
            "Bwd IAT Mean":                bwd_iat_mean,
            "Bwd IAT Std":                 bwd_iat_std,
            "Bwd IAT Max":                 bwd_iat_max,
            "Bwd IAT Min":                 bwd_iat_min,
            "Fwd PSH Flags":               fwd_psh,
            "Bwd PSH Flags":               bwd_psh,
            "Fwd URG Flags":               fwd_urg,
            "Bwd URG Flags":               bwd_urg,
            "Fwd Header Length":           fwd_hdr,
            "Bwd Header Length":           bwd_hdr,
            "Fwd Packets/s":               (len(f) / dur_s) if dur_s > 0 else 0.0,
            "Bwd Packets/s":               (len(b) / dur_s) if dur_s > 0 else 0.0,
            "Min Packet Length":           _safe(all_lens, min),
            "Max Packet Length":           _safe(all_lens, max),
            "Packet Length Mean":          pkt_mean,
            "Packet Length Std":           pkt_std,
            "Packet Length Variance":      pkt_var,
            "FIN Flag Count":              fin_cnt,
            "SYN Flag Count":              syn_cnt,
            "RST Flag Count":              rst_cnt,
            "PSH Flag Count":              psh_cnt,
            "ACK Flag Count":              ack_cnt,
            "URG Flag Count":              urg_cnt,
            "CWE Flag Count":              cwe_cnt,
            "ECE Flag Count":              ece_cnt,
            "Down/Up Ratio":               down_up,
            "Average Packet Size":         pkt_mean,
            "Avg Fwd Segment Size":        fwd_mean,
            "Avg Bwd Segment Size":        bwd_mean,
            "Fwd Avg Bytes/Bulk":          0.0,
            "Fwd Avg Packets/Bulk":        0.0,
            "Fwd Avg Bulk Rate":           0.0,
            "Bwd Avg Bytes/Bulk":          0.0,
            "Bwd Avg Packets/Bulk":        0.0,
            "Bwd Avg Bulk Rate":           0.0,
            "Subflow Fwd Packets":         len(f),
            "Subflow Fwd Bytes":           fwd_tot_len,
            "Subflow Bwd Packets":         len(b),
            "Subflow Bwd Bytes":           bwd_tot_len,
            "Init_Win_bytes_forward":      init_fwd_win,
            "Init_Win_bytes_backward":     init_bwd_win,
            "act_data_pkt_fwd":            act_fwd,
            "min_seg_size_forward":        min_seg_fwd,
            "Active Mean":                 act_mean,
            "Active Std":                  act_std,
            "Active Max":                  act_max,
            "Active Min":                  act_min,
            "Idle Mean":                   idle_mean,
            "Idle Std":                    idle_std,
            "Idle Max":                    idle_max,
            "Idle Min":                    idle_min,
            "Fwd Header Length.1":         fwd_hdr,   # duplicate, used by model
        }


# ──────────────────────────────────────────────────────────────────────────────
# Main extraction function
# ──────────────────────────────────────────────────────────────────────────────
def extract_flows_from_pcap(pcap_path: str, output_dir: str) -> str:
    """
    Parse a PCAP file and export a model-ready flow CSV.

    Args:
        pcap_path:  Path to input .pcap file
        output_dir: Directory to save the CSV

    Returns:
        Path to the generated CSV file
    """
    os.makedirs(output_dir, exist_ok=True)
    stem     = Path(pcap_path).stem
    out_csv  = os.path.join(output_dir, f"{stem}_pyguard_flows.csv")

    # Flow table: key → _Flow
    flows: dict = {}
    finished: list = []

    def _flow_key(p, canonical=False):
        """5-tuple key.  canonical=True → bidirectional (order-independent)."""
        a = (p["src_ip"], p["src_port"])
        b = (p["dst_ip"], p["dst_port"])
        forward = (a, b, p["proto"])
        reverse = (b, a, p["proto"])
        if canonical:
            return min(forward, reverse)
        return forward

    # ── Detect PCAP link type from global header ──────────────────────────────
    # Bytes 20-23 of the PCAP file header = network (link-type) field
    link_type = 1          # default: Ethernet
    try:
        with open(os.path.abspath(pcap_path), "rb") as _f:
            hdr = _f.read(24)
        if len(hdr) == 24:
            magic = int.from_bytes(hdr[:4], "little")
            if magic in (0xA1B2C3D4, 0xA1B23C4D):
                link_type = int.from_bytes(hdr[20:24], "little")
            else:  # big endian
                link_type = int.from_bytes(hdr[20:24], "big")
    except Exception:
        pass

    # link_type=1 → Ethernet, 101 → raw IPv4, 0/12 → loopback BSD/Linux
    if link_type == 1:
        from scapy.layers.l2 import Ether as _Frame
    elif link_type in (0, 12):
        from scapy.layers.inet import IP as _Frame   # BSD/Linux loopback
    else:
        # link_type 101 (raw IP) or anything else — try IP directly
        from scapy.layers.inet import IP as _Frame

    n_pkts = 0
    reader = RawPcapReader(os.path.abspath(pcap_path))

    for raw, meta in reader:
        ts = meta.sec + meta.usec / 1_000_000
        try:
            pkt = _Frame(raw)
            parsed = _parse_packet(pkt, ts)
        except Exception:
            continue


        if parsed is None:
            continue

        n_pkts += 1

        fwd_key = _flow_key(parsed)
        rev_key = (parsed["dst_ip"], parsed["dst_port"]), \
                  (parsed["src_ip"], parsed["src_port"]), parsed["proto"]

        # Check if FIN / RST in any established flow
        key = None
        if fwd_key in flows:
            key = fwd_key
        else:
            # Build the reverse key tuple
            rev = ((parsed["dst_ip"], parsed["dst_port"]),
                   (parsed["src_ip"], parsed["src_port"]),
                   parsed["proto"])
            if rev in flows:
                key = rev

        # Expire old flows first
        expired_keys = [k for k, fl in flows.items() if fl.is_expired(ts)]
        for k in expired_keys:
            feat = flows[k].to_features()
            if feat:
                finished.append(feat)
            del flows[k]

        if key and key in flows:
            flows[key].add(parsed)
            if flows[key].should_close(parsed):
                feat = flows[key].to_features()
                if feat:
                    finished.append(feat)
                del flows[key]
        else:
            # New flow — compute forward key fresh
            new_key = ((parsed["src_ip"], parsed["src_port"]),
                       (parsed["dst_ip"], parsed["dst_port"]),
                       parsed["proto"])
            flows[new_key] = _Flow(parsed)

    # Flush remaining flows
    for fl in flows.values():
        feat = fl.to_features()
        if feat:
            finished.append(feat)

    print(f"  Parsed {n_pkts} packets → {len(finished)} flows")

    if not finished:
        # Write empty CSV with headers so downstream code doesn't crash
        pd.DataFrame(columns=MODEL_COLUMNS).to_csv(out_csv, index=False)
        print(f"  WARNING: No flows extracted from {pcap_path}")
        return out_csv

    df = pd.DataFrame(finished)

    # Ensure all model columns present and in correct order
    for col in MODEL_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0

    df = df[MODEL_COLUMNS]
    df.replace([float("inf"), float("-inf")], 0, inplace=True)
    df.fillna(0, inplace=True)

    df.to_csv(out_csv, index=False)
    print(f"  Saved: {out_csv}  ({len(df)} flows, {len(df.columns)} features)")
    return out_csv


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python pyguard_flow_extractor.py <input.pcap> <output_dir>")
        sys.exit(1)
    result = extract_flows_from_pcap(sys.argv[1], sys.argv[2])
    print("Done:", result)
