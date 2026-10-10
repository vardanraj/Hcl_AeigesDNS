"""Unit tests for pcap_parser.py and magic byte validation."""

import pytest
from pathlib import Path
from backend.app.ingest.pcap_parser import validate_pcap_magic_bytes, parse_pcap_file
from backend.app.utils.synthetic_gen import generate_synthetic_pcap


def test_validate_pcap_magic_bytes_invalid(tmp_path):
    invalid_file = tmp_path / "fake.pcap"
    invalid_file.write_bytes(b"INVALID_HEADER_12345")
    assert validate_pcap_magic_bytes(invalid_file) is False


def test_pcap_parser_with_synthetic_pcap(tmp_path):
    pcap_path = tmp_path / "test_sample.pcap"
    generate_synthetic_pcap(pcap_path, num_records=20)

    assert validate_pcap_magic_bytes(pcap_path) is True
    records = parse_pcap_file(pcap_path, is_synthetic=True)
    assert len(records) > 0
    assert "qname" in records[0]
    assert "src_ip" in records[0]
    assert records[0]["is_synthetic"] is True
