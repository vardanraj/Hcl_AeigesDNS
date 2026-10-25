"""PCAP/PCAPNG packet parser and magic bytes validator.

Parses network capture files using Scapy, validating file signatures
and extracting structured DNS packet records for feature extraction.
"""

from pathlib import Path
from typing import List, Dict, Any, Union
import os
import pandas as pd
from scapy.all import rdpcap, DNS, DNSQR, IP, IPv6, UDP, TCP


# Known PCAP / PCAPNG magic byte signatures
VALID_PCAP_MAGIC_BYTES = [
    b"\xa1\xb2\xc3\xd4",  # Standard PCAP (Big Endian)
    b"\xd4\xc3\xb2\xa1",  # Standard PCAP (Little Endian)
    b"\xa1\xb2\x4c\x4d",  # Nanosecond PCAP (Big Endian)
    b"\x4d\x4c\xb2\xa1",  # Nanosecond PCAP (Little Endian)
    b"\x0a\x0d\x0d\x0a",  # PCAPNG Block Header
]

MAX_PARSE_PACKETS = 50000

QTYPE_MAP = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


def validate_pcap_magic_bytes(file_path: Union[str, Path]) -> bool:
    """Verify if file starts with valid PCAP or PCAPNG magic bytes header.

    Args:
        file_path: Path to the file to check.

    Returns:
        True if valid magic bytes match, False otherwise.
    """
    path = Path(file_path)
    if not path.exists() or path.stat().st_size < 4:
        return False

    with open(path, "rb") as f:
        header = f.read(4)

    return any(header.startswith(magic) for magic in VALID_PCAP_MAGIC_BYTES)


def parse_pcap_file(file_path: Union[str, Path], is_synthetic: bool = True) -> List[Dict[str, Any]]:
    """Parse a PCAP or PCAPNG file and extract DNS query records.

    Args:
        file_path: Path to PCAP file.
        is_synthetic: Flag indicating whether this dataset is synthetic.

    Returns:
        List of dictionaries containing parsed DNS records.
    """
    path = Path(file_path)
    if not validate_pcap_magic_bytes(path):
        raise ValueError("Invalid PCAP file header or unsupported format.")

    try:
        packets = rdpcap(str(path))
    except Exception as e:
        raise ValueError(f"Failed to read PCAP file with Scapy: {str(e)}")

    if len(packets) > MAX_PARSE_PACKETS:
        raise ValueError(f"PCAP packet count ({len(packets)}) exceeds maximum allowed limit of {MAX_PARSE_PACKETS} packets.")

    records: List[Dict[str, Any]] = []

    for pkt in packets:
        if not pkt.haslayer(DNS):
            continue

        dns = pkt.getlayer(DNS)
        # Process DNS query layer
        if dns.qr == 0 and dns.qdcount > 0 and pkt.haslayer(DNSQR):
            dnsqr = pkt.getlayer(DNSQR)

            # Determine IP addresses
            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst

            # Format qname string
            raw_qname = dnsqr.qname
            if isinstance(raw_qname, bytes):
                qname_str = raw_qname.decode("utf-8", errors="ignore").rstrip(".")
            else:
                qname_str = str(raw_qname).rstrip(".")

            qtype_int = int(dnsqr.qtype)
            qtype_str = QTYPE_MAP.get(qtype_int, f"TYPE{qtype_int}")

            pkt_time = float(pkt.time)
            payload_len = len(pkt)

            records.append({
                "timestamp": pkt_time,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "qname": qname_str,
                "qtype": qtype_str,
                "qclass": "IN",
                "rcode": "NOERROR",
                "payload_len": payload_len,
                "is_synthetic": is_synthetic,
            })

    return records


def parse_pcap_to_dataframe(file_path: Union[str, Path], is_synthetic: bool = True) -> pd.DataFrame:
    """Parse PCAP file directly into a Pandas DataFrame.

    Args:
        file_path: Path to PCAP file.
        is_synthetic: Flag indicating whether this dataset is synthetic.

    Returns:
        Pandas DataFrame containing DNS records.
    """
    records = parse_pcap_file(file_path, is_synthetic=is_synthetic)
    if not records:
        return pd.DataFrame(columns=[
            "timestamp", "src_ip", "dst_ip", "qname", "qtype", "qclass", "rcode", "payload_len", "is_synthetic"
        ])
    return pd.DataFrame(records)
