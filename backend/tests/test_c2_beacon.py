"""Unit tests for c2_beacon.py periodic heartbeat detection."""

from backend.app.analytics.c2_beacon import C2BeaconDetector
from backend.app.utils.synthetic_gen import generate_synthetic_dns_records
from backend.app.analytics.feature_extractor import extract_dns_features


def test_c2_beacon_detection():
    detector = C2BeaconDetector()

    # Periodic timestamp sequence (exactly 10s intervals)
    periodic_ts = [100.0, 110.0, 120.0, 130.0, 140.0, 150.0]
    mean_int, std_dev, cv, is_beacon = detector.analyze_domain_group("192.168.1.10", "c2.net", periodic_ts)

    assert is_beacon is True
    assert mean_int == 10.0
    assert cv < 0.05

    # Random timestamp sequence (high jitter)
    random_ts = [100.0, 102.0, 145.0, 148.0, 300.0, 310.0]
    r_mean, r_std, r_cv, r_beacon = detector.analyze_domain_group("192.168.1.10", "c2.net", random_ts)

    assert r_beacon is False
    assert r_cv > 0.5


def test_c2_beacon_fires_on_synthetic_beacon_families():
    """Assert C2 beacon detector fires on synthetic periodic beaconing attack families."""
    records = generate_synthetic_dns_records(num_records=300, tunnel_ratio=0.30)
    enriched = [extract_dns_features(r) for r in records]

    detector = C2BeaconDetector()
    alerts = detector.detect_beacons(enriched)

    assert len(alerts) >= 2
    domains_alerted = set(a.evidence["base_domain"] for a in alerts)
    assert "dns-tunnel-gamma.org" in domains_alerted or "stealth-theta.xyz" in domains_alerted or "tunnel-eta.cc" in domains_alerted
