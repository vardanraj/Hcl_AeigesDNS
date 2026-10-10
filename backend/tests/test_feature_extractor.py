"""Unit tests for feature_extractor.py entropy and character ratio math."""

from backend.app.analytics.feature_extractor import (
    calculate_shannon_entropy,
    extract_base_and_subdomain,
    extract_dns_features,
)


def test_shannon_entropy_calculation():
    # Constant string has 0 entropy
    assert calculate_shannon_entropy("aaaaaaa") == 0.0
    # High entropy string (all unique chars)
    ent = calculate_shannon_entropy("abcdefghijk")
    assert ent > 3.0


def test_extract_base_and_subdomain():
    sub, base = extract_base_and_subdomain("abc.def.example.com")
    assert sub == "abc.def"
    assert base == "example.com"

    sub2, base2 = extract_base_and_subdomain("google.com")
    assert sub2 == ""
    assert base2 == "google.com"


def test_extract_dns_features():
    raw_rec = {
        "qname": "a1b2c3d4e5f6.tunnel.example.com",
        "src_ip": "192.168.1.10",
        "qtype": "TXT",
    }
    feat = extract_dns_features(raw_rec)
    assert feat["base_domain"] == "example.com"
    assert feat["subdomain"] == "a1b2c3d4e5f6.tunnel"
    assert feat["subdomain_len"] > 10
    assert feat["hex_ratio"] > 0.5
    assert feat["entropy"] > 3.0
