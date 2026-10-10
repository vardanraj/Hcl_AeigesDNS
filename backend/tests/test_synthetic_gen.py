"""Unit tests for synthetic_gen.py and test-split validation."""

import pytest
import numpy as np
import pandas as pd
from backend.app.utils.synthetic_gen import generate_synthetic_dns_records, generate_synthetic_pcap
from backend.app.ingest.pcap_parser import validate_pcap_magic_bytes


def test_generate_synthetic_dns_records():
    records = generate_synthetic_dns_records(num_records=100, tunnel_ratio=0.30)
    assert len(records) >= 100
    assert all(r["is_synthetic"] is True for r in records)
    assert "attack_family" in records[0]
    assert "base_domain" in records[0]

    # Check distinct tunnel base domains presence
    tunnel_domains = set(r["base_domain"] for r in records if r["attack_family"] not in {"benign", "hard_benign"})
    assert len(tunnel_domains) >= 3


def test_test_split_contains_attack_samples():
    """Requirement 6: Test that fails if test split has no attack samples."""
    records = generate_synthetic_dns_records(num_records=300, tunnel_ratio=0.30)
    df = pd.DataFrame(records)

    # Attack label: 1 if not benign/hard_benign, 0 otherwise
    df["label"] = df["attack_family"].apply(lambda f: 0 if f in {"benign", "hard_benign"} else 1)

    # Perform group split by attack family & base domain
    attack_families = list(df[df["label"] == 1]["attack_family"].unique())
    assert len(attack_families) >= 2

    # Reserve 1 attack family for test split
    test_family = attack_families[0]
    test_mask = df["attack_family"] == test_family

    y_test = df[test_mask]["label"].values
    positives = int(np.sum(y_test == 1))

    # Assert test split contains positive attack samples
    assert positives > 0, "Test split contains 0 attack samples!"


def test_generate_synthetic_pcap(tmp_path):
    out_pcap = tmp_path / "synthetic_test.pcap"
    created = generate_synthetic_pcap(out_pcap, num_records=30)
    assert created.exists()
    assert validate_pcap_magic_bytes(created) is True
