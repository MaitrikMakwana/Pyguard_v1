"""
PyGuard Synthetic Attack PCAP Generator
=========================================
Generates 6 realistic labeled PCAP files for industry-level testing:
  1. benign_traffic.pcap    – Normal HTTP/DNS/HTTPS/SSH
  2. dos_syn_flood.pcap     – DoS SYN flood (TCP, high rate, no response)
  3. dos_udp_flood.pcap     – DoS UDP flood (large packets, high rate)
  4. dos_slowloris.pcap     – DoS slow HTTP (many half-open connections)
  5. ddos_multihost.pcap    – DDoS SYN flood from 200 source IPs
  6. portscan.pcap          – PortScan (sequential SYN to ports 1-1024)

Usage:
    python scripts/generate_attack_pcaps.py
    python scripts/generate_attack_pcaps.py --output-dir <dir>
"""

import os
import sys
import random
import argparse
import struct
import time
from pathlib import Path

try:
    from scapy.all import (
        IP, TCP, UDP, DNS, DNSQR, Raw, Ether,
        wrpcap, RandMAC
    )
    from scapy.layers.http import HTTP, HTTPRequest
except ImportError:
    # scapy may not have HTTP layer built-in on all versions — that's OK
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, Ether, wrpcap, RandMAC

random.seed(42)

# ── Configuration ─────────────────────────────────────────────────────────────
TARGET_IP   = "192.168.1.100"
GATEWAY_IP  = "192.168.1.1"
DNS_SERVER  = "8.8.8.8"
ATTACKER_IP = "10.0.0.50"

def _rand_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def _rand_port():
    return random.randint(1024, 65535)

def _ts_seq(start, count, interval_s):
    """Return list of `count` synthetic timestamps at `interval_s` apart."""
    return [start + i * interval_s for i in range(count)]


# ══════════════════════════════════════════════════════════════════════════════
# 1.  BENIGN TRAFFIC
# ══════════════════════════════════════════════════════════════════════════════
def gen_benign(output_path):
    print("  Generating benign_traffic.pcap ...")
    pkts = []
    base_ts = time.time() - 300   # 5 minutes ago

    client_ip = "192.168.1.10"
    server_ip = TARGET_IP

    # ── HTTP GET sessions (50 flows × ~10 packets each) ──────────────────────
    for flow_idx in range(50):
        sport = _rand_port()
        ts    = base_ts + flow_idx * 5.0
        seq   = random.randint(100000, 999999)

        # SYN
        p = IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=80,
              flags="S", seq=seq, window=65535)
        p.time = ts;  pkts.append(p)
        # SYN-ACK
        p = IP(src=server_ip, dst=client_ip) / TCP(sport=80, dport=sport,
              flags="SA", seq=random.randint(1,1000000), ack=seq+1, window=65535)
        p.time = ts+0.001;  pkts.append(p)
        # ACK
        p = IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=80,
              flags="A", seq=seq+1, window=65535)
        p.time = ts+0.002;  pkts.append(p)
        # GET request
        http_payload = f"GET /index.html HTTP/1.1\r\nHost: {server_ip}\r\n\r\n".encode()
        p = IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=80,
              flags="PA", seq=seq+1) / Raw(load=http_payload)
        p.time = ts+0.003;  pkts.append(p)
        # HTTP 200 response
        resp = b"HTTP/1.1 200 OK\r\nContent-Length: 512\r\n\r\n" + b"X"*512
        p = IP(src=server_ip, dst=client_ip) / TCP(sport=80, dport=sport,
              flags="PA") / Raw(load=resp)
        p.time = ts+0.015;  pkts.append(p)
        # ACK + FIN
        for flags, dt in [("A", 0.016), ("FA", 0.017)]:
            p = IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=80,
                  flags=flags, seq=seq+len(http_payload)+1)
            p.time = ts+dt;  pkts.append(p)

    # ── DNS queries (100 queries) ─────────────────────────────────────────────
    domains = ["google.com", "github.com", "microsoft.com", "amazon.com", "youtube.com"]
    for i in range(100):
        ts = base_ts + 250 + i * 0.3
        domain = random.choice(domains)
        p = IP(src=client_ip, dst=DNS_SERVER) / UDP(sport=_rand_port(), dport=53) / \
            DNS(rd=1, qd=DNSQR(qname=domain))
        p.time = ts;  pkts.append(p)
        # DNS response
        p = IP(src=DNS_SERVER, dst=client_ip) / UDP(sport=53, dport=_rand_port()) / \
            Raw(load=b"\x00"*40)
        p.time = ts+0.02;  pkts.append(p)

    # ── SSH sessions (10 flows) ───────────────────────────────────────────────
    for i in range(10):
        sport = _rand_port()
        ts    = base_ts + 200 + i * 15.0
        for j in range(20):
            size = random.randint(100, 1400)
            p = IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=22,
                  flags="PA") / Raw(load=os.urandom(size))
            p.time = ts + j*0.5;  pkts.append(p)
            p = IP(src=server_ip, dst=client_ip) / TCP(sport=22, dport=sport,
                  flags="PA") / Raw(load=os.urandom(random.randint(50,200)))
            p.time = ts + j*0.5 + 0.05;  pkts.append(p)

    pkts.sort(key=lambda p: p.time)
    wrpcap(output_path, pkts)
    print(f"    Saved {len(pkts)} packets → {output_path}")


# ══════════════════════════════════════════════════════════════════════════════
# 2. DoS SYN FLOOD
# ══════════════════════════════════════════════════════════════════════════════
def gen_dos_syn_flood(output_path):
    print("  Generating dos_syn_flood.pcap ...")
    pkts = []
    base_ts = time.time() - 300

    # 5000 SYN packets at ~2000 pkt/s (IAT ≈ 0.5 ms)
    for i in range(5000):
        ts = base_ts + i * 0.0005    # 0.5 ms interval
        p = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(
            sport=random.randint(1024, 65535),
            dport=80,
            flags="S",
            seq=random.randint(100000, 999999),
            window=1024
        )
        p.time = ts
        pkts.append(p)

    # A handful of real SYN-ACK replies from target (shows response exhaustion)
    for i in range(20):
        p = IP(src=TARGET_IP, dst=ATTACKER_IP) / TCP(
            sport=80, dport=random.randint(1024,65535),
            flags="SA", window=0
        )
        p.time = base_ts + i * 0.5
        pkts.append(p)

    pkts.sort(key=lambda p: p.time)
    wrpcap(output_path, pkts)
    print(f"    Saved {len(pkts)} packets → {output_path}")


# ══════════════════════════════════════════════════════════════════════════════
# 3. DoS UDP FLOOD
# ══════════════════════════════════════════════════════════════════════════════
def gen_dos_udp_flood(output_path):
    print("  Generating dos_udp_flood.pcap ...")
    pkts = []
    base_ts = time.time() - 300

    # 3000 large UDP packets  → high bytes/s
    for i in range(3000):
        ts = base_ts + i * 0.001    # 1 ms interval = 1000 pkt/s
        payload_size = random.randint(900, 1400)
        p = IP(src=ATTACKER_IP, dst=TARGET_IP) / UDP(
            sport=random.randint(1024, 65535),
            dport=random.choice([53, 80, 443, 19, 17])
        ) / Raw(load=os.urandom(payload_size))
        p.time = ts
        pkts.append(p)

    pkts.sort(key=lambda p: p.time)
    wrpcap(output_path, pkts)
    print(f"    Saved {len(pkts)} packets → {output_path}")


# ══════════════════════════════════════════════════════════════════════════════
# 4. DoS SLOWLORIS (slow HTTP)
# ══════════════════════════════════════════════════════════════════════════════
def gen_dos_slowloris(output_path):
    print("  Generating dos_slowloris.pcap ...")
    pkts = []
    base_ts = time.time() - 600   # 10 minutes of data

    # 200 slow sessions: open connection, send headers one line at a time
    for session in range(200):
        sport = 10000 + session
        ts    = base_ts + session * 0.1
        seq   = random.randint(100000, 999999)

        # SYN
        p = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=sport, dport=80,
              flags="S", seq=seq, window=65535)
        p.time = ts;  pkts.append(p)
        # SYN-ACK
        p = IP(src=TARGET_IP, dst=ATTACKER_IP) / TCP(sport=80, dport=sport,
              flags="SA", window=65535)
        p.time = ts+0.01;  pkts.append(p)
        # ACK
        p = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=sport, dport=80,
              flags="A", seq=seq+1, window=65535)
        p.time = ts+0.02;  pkts.append(p)
        # Send partial HTTP headers very slowly (one line every ~5s)
        partial_headers = [
            b"GET / HTTP/1.1\r\n",
            b"Host: target.local\r\n",
            b"X-Padding: " + b"A"*100 + b"\r\n",
        ]
        for j, hdr in enumerate(partial_headers):
            p = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=sport, dport=80,
                  flags="PA", seq=seq+1) / Raw(load=hdr)
            p.time = ts + 0.03 + j*5.0
            pkts.append(p)
            # Keep-alive ACK from server
            p = IP(src=TARGET_IP, dst=ATTACKER_IP) / TCP(sport=80, dport=sport,
                  flags="A", window=65535)
            p.time = ts + 0.04 + j*5.0
            pkts.append(p)

    pkts.sort(key=lambda p: p.time)
    wrpcap(output_path, pkts)
    print(f"    Saved {len(pkts)} packets → {output_path}")


# ══════════════════════════════════════════════════════════════════════════════
# 5. DDoS MULTI-HOST SYN FLOOD
# ══════════════════════════════════════════════════════════════════════════════
def gen_ddos_multihost(output_path):
    print("  Generating ddos_multihost.pcap ...")
    pkts = []
    base_ts = time.time() - 300

    # 200 distinct source IPs, each sending 100 SYN packets
    source_ips = [_rand_ip() for _ in range(200)]

    for bot_ip in source_ips:
        for i in range(100):
            ts = base_ts + random.uniform(0, 60)       # spread over 60 s
            p = IP(src=bot_ip, dst=TARGET_IP) / TCP(
                sport=random.randint(1024, 65535),
                dport=80,
                flags="S",
                seq=random.randint(100000, 999999),
                window=512
            )
            p.time = ts
            pkts.append(p)

    pkts.sort(key=lambda p: p.time)
    wrpcap(output_path, pkts)
    print(f"    Saved {len(pkts)} packets → {output_path}")


# ══════════════════════════════════════════════════════════════════════════════
# 6. PORT SCAN
# ══════════════════════════════════════════════════════════════════════════════
def gen_portscan(output_path):
    print("  Generating portscan.pcap ...")
    pkts = []
    base_ts = time.time() - 300

    # SYN to ports 1-1024
    for port in range(1, 1025):
        ts = base_ts + port * 0.005    # 5 ms between ports
        p = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(
            sport=random.randint(40000, 60000),
            dport=port,
            flags="S",
            seq=random.randint(100000, 999999),
            window=1024
        )
        p.time = ts
        pkts.append(p)

        # RST or SYN-ACK reply for open ports (21, 22, 80, 443, 3306...)
        open_ports = {21, 22, 25, 80, 110, 143, 443, 3306, 3389, 5432, 8080}
        if port in open_ports:
            reply_flags = "SA"
        else:
            reply_flags = "R"
        p = IP(src=TARGET_IP, dst=ATTACKER_IP) / TCP(
            sport=port,
            dport=p[TCP].sport,
            flags=reply_flags,
            window=65535 if reply_flags == "SA" else 0
        )
        p.time = ts + 0.001
        pkts.append(p)

    pkts.sort(key=lambda p: p.time)
    wrpcap(output_path, pkts)
    print(f"    Saved {len(pkts)} packets → {output_path}")


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="PyGuard Synthetic Attack PCAP Generator")
    parser.add_argument(
        "--output-dir",
        default=r"d:\PyGuard-main\Final_IDS\Testing Files",
        help="Directory to write generated PCAP files"
    )
    args = parser.parse_args()

    out = args.output_dir
    os.makedirs(out, exist_ok=True)

    print(f"Generating synthetic attack PCAPs in: {out}\n")

    generators = [
        ("benign_traffic.pcap",   gen_benign),
        ("dos_syn_flood.pcap",    gen_dos_syn_flood),
        ("dos_udp_flood.pcap",    gen_dos_udp_flood),
        ("dos_slowloris.pcap",    gen_dos_slowloris),
        ("ddos_multihost.pcap",   gen_ddos_multihost),
        ("portscan.pcap",         gen_portscan),
    ]

    results = []
    for filename, gen_fn in generators:
        path = os.path.join(out, filename)
        try:
            gen_fn(path)
            size_kb = os.path.getsize(path) / 1024
            results.append((filename, size_kb, "OK"))
        except Exception as e:
            print(f"  ERROR generating {filename}: {e}")
            results.append((filename, 0, f"ERROR: {e}"))

    print("\n── Generated Files ────────────────────────────────────────────────")
    print(f"{'File':<30} {'Size':>10}  Status")
    print("-"*55)
    for name, size_kb, status in results:
        print(f"{name:<30} {size_kb:>8.1f} KB  {status}")
    print(f"\nOutput dir: {out}")


if __name__ == "__main__":
    main()
