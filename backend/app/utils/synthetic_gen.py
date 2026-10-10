"""Synthetic DNS Traffic Generator for AegisDNS.

Generates realistic benign DNS queries, hard-benign high-entropy queries
(CDNs up to 40 chars, AV lookups, DKIM, mixed-case names), and varied tunneled
attack families across at least 8 distinct tunnel base domains.
"""

from typing import List, Dict, Any, Union
from pathlib import Path
import random
import time
import base64
import string
from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap

# Legitimate standard domains (25+ distinct domains)
BENIGN_DOMAINS = [
    "google.com", "github.com", "wikipedia.org", "microsoft.com",
    "stackoverflow.com", "reddit.com", "amazon.com", "apple.com",
    "cloudflare.com", "netflix.com", "linkedin.com", "dropbox.com",
    "salesforce.com", "zoom.us", "slack.com", "spotify.com",
    "mozilla.org", "adobe.com", "nytimes.com", "cnn.com",
    "medium.com", "quora.com", "twitter.com", "uber.com", "airbnb.com"
]

# Hard-benign patterns (high entropy, long, mixed case, DKIM, AV lookups, CDNs)
HARD_BENIGN_PATTERNS = [
    "{hash40}.akamaiedge.net",
    "{hash32}.cloudfront.net",
    "{hash32}.sophosxl.net",
    "{hash24}.vba.kaspersky.com",
    "{hash32}.fastly.net",
    "{hash24}.digicert.com",
    "s20230101._domainkey.mail.{domain}",
    "_spf.{domain}",
    "API-Server-V2.DevHost.{domain}",
    "Auth-Service-Node-42.{domain}"
]

# 8+ distinct Tunnel & C2 base domains
TUNNEL_BASE_DOMAINS = [
    "c2-alpha.net",
    "exfil-beta.com",
    "dns-tunnel-gamma.org",
    "beacon-delta.info",
    "covert-epsilon.io",
    "shadow-zeta.biz",
    "tunnel-eta.cc",
    "stealth-theta.xyz"
]

# Diverse attack families
ATTACK_FAMILIES = [
    "iodine_base32",
    "dnscat2_hex",
    "cobalt_strike_txt",
    "low_and_slow_exfil",
    "dict_words_c2"
]

SOURCE_IPS = [
    "192.168.1.105", "192.168.1.110", "10.0.0.45", "172.16.0.88",
    "192.168.1.150", "10.0.1.22", "192.168.1.210", "10.0.2.99"
]

DICTIONARY_WORDS = ["chunk", "val", "token", "data", "payload", "stream", "packet", "segment", "node", "sys"]


def _random_hex(length: int) -> str:
    return "".join(random.choices("0123456789abcdef", k=length))


def _random_base32(length: int) -> str:
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyz234567", k=length))


def _random_base64_urlsafe(length: int) -> str:
    chars = string.ascii_letters + string.digits + "-_"
    return "".join(random.choices(chars, k=length))


def _random_dict_chunks(length: int) -> str:
    parts = []
    curr_len = 0
    while curr_len < length:
        w = random.choice(DICTIONARY_WORDS) + str(random.randint(10, 999))
        parts.append(w)
        curr_len += len(w) + 1
    return ".".join(parts)[:length].rstrip(".")


def generate_synthetic_dns_records(num_records: int = 300, tunnel_ratio: float = 0.30) -> List[Dict[str, Any]]:
    """Generate rich synthetic DNS query records with varied encodings, record types, and attack families.

    Args:
        num_records: Total number of records to generate.
        tunnel_ratio: Ratio of tunneled/anomalous queries.

    Returns:
        List of synthetic DNS query record dictionaries.
    """
    records: List[Dict[str, Any]] = []
    base_time = time.time() - (num_records * 3)

    num_tunnel = int(num_records * tunnel_ratio)
    num_hard_benign = int(num_records * 0.25)
    num_standard = num_records - num_tunnel - num_hard_benign

    # 1. Standard Benign Queries
    for i in range(num_standard):
        domain = random.choice(BENIGN_DOMAINS)
        sub = random.choice(["www", "api", "mail", "cdn", "dev", ""])
        qname = f"{sub}.{domain}" if sub else domain
        records.append({
            "timestamp": base_time + (i * 1.5) + random.uniform(-0.3, 0.3),
            "src_ip": random.choice(SOURCE_IPS[:4]),
            "dst_ip": "8.8.8.8",
            "qname": qname,
            "subdomain": sub,
            "base_domain": domain,
            "qtype": random.choice(["A", "AAAA"]),
            "qclass": "IN",
            "rcode": "NOERROR",
            "payload_len": len(qname) + 28,
            "is_synthetic": True,
            "attack_family": "benign",
        })

    # 2. Hard-Benign Queries (Long, High Entropy, CDNs up to 40 chars, DKIM, AV lookups)
    for i in range(num_hard_benign):
        pattern = random.choice(HARD_BENIGN_PATTERNS)
        h40 = _random_hex(40)
        h32 = _random_hex(32)
        h24 = _random_hex(24)
        d = random.choice(BENIGN_DOMAINS)
        qname = pattern.format(hash40=h40, hash32=h32, hash24=h24, domain=d)

        # Base domain calculation
        parts = qname.split(".")
        bdom = ".".join(parts[-2:]) if len(parts) >= 2 else qname

        records.append({
            "timestamp": base_time + (i * 2.0) + random.uniform(-0.2, 0.2),
            "src_ip": random.choice(SOURCE_IPS[:4]),
            "dst_ip": "1.1.1.1",
            "qname": qname,
            "subdomain": ".".join(parts[:-2]) if len(parts) > 2 else "",
            "base_domain": bdom,
            "qtype": random.choice(["A", "TXT", "AAAA"]),
            "qclass": "IN",
            "rcode": "NOERROR",
            "payload_len": len(qname) + 30,
            "is_synthetic": True,
            "attack_family": "hard_benign",
        })

    # 3. Tunneled & C2 Queries structured by attack family sequences
    base_specs = [
        {"family": "iodine_base32", "domain": "covert-epsilon.io", "src_ip": "10.0.0.45", "base_count": 18, "mode": "exfil"},
        {"family": "iodine_base32", "domain": "c2-alpha.net", "src_ip": "10.0.1.22", "base_count": 16, "mode": "exfil"},
        {"family": "dnscat2_hex", "domain": "exfil-beta.com", "src_ip": "172.16.0.88", "base_count": 18, "mode": "exfil"},
        {"family": "dnscat2_hex", "domain": "shadow-zeta.biz", "src_ip": "192.168.1.150", "base_count": 16, "mode": "exfil"},
        {"family": "cobalt_strike_txt", "domain": "dns-tunnel-gamma.org", "src_ip": "192.168.1.210", "base_count": 10, "mode": "beacon", "interval": 10.0},
        {"family": "cobalt_strike_txt", "domain": "tunnel-eta.cc", "src_ip": "10.0.2.99", "base_count": 10, "mode": "beacon", "interval": 15.0},
        {"family": "low_and_slow_exfil", "domain": "beacon-delta.info", "src_ip": "192.168.1.150", "base_count": 16, "mode": "exfil"},
        {"family": "dict_words_c2", "domain": "stealth-theta.xyz", "src_ip": "10.0.2.99", "base_count": 8, "mode": "beacon", "interval": 12.0},
    ]

    total_base_count = sum(s["base_count"] for s in base_specs)
    scale_factor = num_tunnel / float(total_base_count) if total_base_count > 0 else 1.0

    for spec in base_specs:
        family = spec["family"]
        domain = spec["domain"]
        src_ip = spec["src_ip"]
        mode = spec["mode"]
        min_c = 16 if mode == "exfil" else 8
        count = max(min_c, int(round(spec["base_count"] * scale_factor)))

        family_start_time = base_time + random.uniform(10.0, 100.0)

        for j in range(count):
            sub_len = random.randint(25, 55)
            if family == "iodine_base32":
                sub_payload = _random_base32(sub_len)
                qtype = random.choice(["TXT", "NULL", "CNAME"])
            elif family == "dnscat2_hex":
                sub_payload = _random_hex(sub_len)
                qtype = random.choice(["CNAME", "TXT", "MX"])
            elif family == "cobalt_strike_txt":
                sub_payload = _random_base64_urlsafe(sub_len)
                qtype = "TXT"
            elif family == "low_and_slow_exfil":
                sub_payload = _random_base32(sub_len)
                qtype = random.choice(["TXT", "A"])
            else:  # dict_words_c2
                sub_payload = _random_dict_chunks(sub_len)
                qtype = random.choice(["A", "TXT"])

            if mode == "beacon":
                # Low-jitter periodic heartbeat timestamp sequence (CV < 0.10)
                ts = family_start_time + (j * spec["interval"]) + random.uniform(-0.08, 0.08)
            else:
                # Exfiltration sequence
                ts = family_start_time + (j * random.uniform(1.0, 3.0))

            qname = f"{sub_payload}.{domain}"
            records.append({
                "timestamp": ts,
                "src_ip": src_ip,
                "dst_ip": "8.8.8.8",
                "qname": qname,
                "subdomain": sub_payload,
                "base_domain": domain,
                "qtype": qtype,
                "qclass": "IN",
                "rcode": "NOERROR",
                "payload_len": len(qname) + 32,
                "is_synthetic": True,
                "attack_family": family,
            })

    # Sort records chronologically
    records.sort(key=lambda r: r["timestamp"])
    return records


def generate_synthetic_pcap(output_path: Union[str, Path], num_records: int = 200) -> Path:
    """Generate synthetic PCAP file containing benign and tunneled DNS queries."""
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    records = generate_synthetic_dns_records(num_records=num_records, tunnel_ratio=0.30)
    packets = []

    # Insert metadata marker packet to identify synthetic PCAP origin
    base_ts = records[0]["timestamp"] - 0.1 if records else time.time()
    marker_pkt = (
        Ether()
        / IP(src="192.168.1.100", dst="8.8.8.8")
        / UDP(sport=53535, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="aegisdns-synthetic-marker.local", qtype=16))
    )
    marker_pkt.time = base_ts
    packets.append(marker_pkt)

    qtype_code_map = {"A": 1, "NS": 2, "CNAME": 5, "NULL": 10, "MX": 15, "TXT": 16, "AAAA": 28}

    for r in records:
        qname = r["qname"]
        qtype_str = r["qtype"]
        qtype_num = qtype_code_map.get(qtype_str, 1)

        pkt = (
            Ether()
            / IP(src=r["src_ip"], dst=r["dst_ip"])
            / UDP(sport=random.randint(1024, 65535), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype_num))
        )
        pkt.time = r["timestamp"]
        packets.append(pkt)

    wrpcap(str(out_file), packets)
    return out_file
