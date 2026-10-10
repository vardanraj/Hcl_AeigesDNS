"""Unit tests for detectors.py rule evaluations."""

from backend.app.analytics.detectors import RuleBasedDetector


def test_rule_detector_triggers():
    detector = RuleBasedDetector()

    # Normal query should not trigger alerts
    normal_rec = {
        "qname": "www.google.com",
        "subdomain": "www",
        "subdomain_len": 3,
        "entropy": 1.5,
        "digit_ratio": 0.0,
        "hex_ratio": 0.0,
        "qtype": "A",
    }
    alerts_normal = detector.evaluate_record(normal_rec)
    assert len(alerts_normal) == 0

    # High entropy & long subdomain record should trigger alerts
    anomalous_rec = {
        "qname": "3c9f2a0b1d8e7f4c5b6a7d8e9f0a1b2c3d4e5f6a.tunnel.evil.com",
        "subdomain": "3c9f2a0b1d8e7f4c5b6a7d8e9f0a1b2c3d4e5f6a.tunnel",
        "subdomain_len": 44,
        "entropy": 4.3,
        "digit_ratio": 0.35,
        "hex_ratio": 0.85,
        "qtype": "TXT",
    }
    alerts_anomalous = detector.evaluate_record(anomalous_rec)
    assert len(alerts_anomalous) >= 2
    rule_names = [a.rule_name for a in alerts_anomalous]
    assert "HIGH_SUBDOMAIN_ENTROPY" in rule_names
    assert "LONG_SUBDOMAIN_LENGTH" in rule_names


def test_allowlisted_mdns_domain_skip():
    """Assert that mDNS/DNS-SD reserved domains (.local, _tcp., _udp.) skip rule scoring."""
    detector = RuleBasedDetector()

    mdns_rec_1 = {
        "qname": "nearby-presence-nsd-82c1bd3a-7d19-47fe-89f5-0748741f361f._nearbypresence._tcp.local",
        "subdomain": "nearby-presence-nsd-82c1bd3a-7d19-47fe-89f5-0748741f361f._nearbypresence",
        "base_domain": "_tcp.local",
        "subdomain_len": 72,
        "entropy": 4.5,
        "digit_ratio": 0.35,
        "hex_ratio": 0.70,
        "qtype": "ANY",
    }
    assert detector.evaluate_record(mdns_rec_1) == []

    mdns_rec_2 = {
        "qname": "printer._tcp.local",
        "subdomain": "printer",
        "base_domain": "_tcp.local",
        "subdomain_len": 7,
        "entropy": 2.5,
        "qtype": "PTR",
    }
    assert detector.evaluate_record(mdns_rec_2) == []

    mdns_rec_3 = {
        "qname": "_services._dns-sd._udp.local",
        "subdomain": "_services._dns-sd",
        "base_domain": "_udp.local",
        "subdomain_len": 17,
        "entropy": 3.0,
        "qtype": "PTR",
    }
    assert detector.evaluate_record(mdns_rec_3) == []

