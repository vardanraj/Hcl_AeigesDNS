"""Unit tests for incident_engine.py risk score fusion and grouping."""

from backend.app.analytics.incident_engine import IncidentEngine
from backend.app.models.schemas import AlertDetail, Incident


def test_incident_engine_fusion():
    engine = IncidentEngine()

    records = [
        {
            "src_ip": "192.168.1.100",
            "base_domain": "evil-c2.org",
            "qname": "3c9f2a0b1d8e7f.evil-c2.org",
            "qtype": "TXT",
            "entropy": 4.2,
            "subdomain_len": 35,
            "timestamp": 1000.0,
        },
        {
            "src_ip": "192.168.1.100",
            "base_domain": "evil-c2.org",
            "qname": "a1b2c3d4e5f6.evil-c2.org",
            "qtype": "TXT",
            "entropy": 4.4,
            "subdomain_len": 40,
            "timestamp": 1010.0,
        },
    ]

    rule_alerts = [
        AlertDetail(
            detector_type="rule",
            rule_name="HIGH_SUBDOMAIN_ENTROPY",
            severity="HIGH",
            description="High entropy",
            score=0.85,
            evidence={"src_ip": "192.168.1.100", "base_domain": "evil-c2.org"},
        )
    ]

    beacon_alerts = [
        AlertDetail(
            detector_type="c2_beacon",
            rule_name="C2_PERIODIC_BEACONING",
            severity="CRITICAL",
            description="Periodic C2",
            score=0.90,
            evidence={"src_ip": "192.168.1.100", "base_domain": "evil-c2.org"},
        )
    ]

    exfil_alerts = [
        AlertDetail(
            detector_type="exfiltration",
            rule_name="DNS_DATA_EXFILTRATION",
            severity="HIGH",
            description="Data exfil",
            score=0.80,
            evidence={"src_ip": "192.168.1.100", "base_domain": "evil-c2.org"},
        )
    ]

    ml_probs = [0.88, 0.92]

    incidents = engine.process_records_and_alerts(
        records, rule_alerts, beacon_alerts, exfil_alerts, ml_probs, is_synthetic=True
    )

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.src_ip == "192.168.1.100"
    assert inc.base_domain == "evil-c2.org"
    assert inc.risk_score >= 80.0
    assert inc.severity == "Critical"
    assert "C2_PERIODIC_BEACONING" in inc.triggered_rules
    assert "DNS_DATA_EXFILTRATION" in inc.triggered_rules
    assert "HIGH_SUBDOMAIN_ENTROPY" in inc.triggered_rules
    assert "Isolate host 192.168.1.100" in inc.recommended_action
    assert inc.is_synthetic is True


def test_allowlisted_tcp_local_no_incident():
    """Assert a real _tcp.local query creates NO incident in IncidentEngine."""
    from backend.app.analytics.feature_extractor import extract_dns_features
    from backend.app.analytics.detectors import RuleBasedDetector
    from backend.app.analytics.c2_beacon import C2BeaconDetector
    from backend.app.analytics.exfiltration import ExfiltrationDetector
    from backend.app.analytics.ml_classifier import MLAnomalyClassifier

    raw_rec = {
        "src_ip": "172.16.5.246",
        "qname": "nearby-presence-nsd-82c1bd3a-7d19-47fe-89f5-0748741f361f._nearbypresence._tcp.local",
        "qtype": "ANY",
        "timestamp": 1790664359.0,
    }
    enriched = [extract_dns_features(raw_rec)]

    rule_detector = RuleBasedDetector()
    beacon_detector = C2BeaconDetector()
    exfil_detector = ExfiltrationDetector()
    ml_classifier = MLAnomalyClassifier()

    rule_alerts = rule_detector.evaluate_batch(enriched)
    beacon_alerts = beacon_detector.detect_beacons(enriched)
    exfil_alerts = exfil_detector.detect_exfiltration(enriched)
    ml_probs = ml_classifier.predict_batch(enriched)

    engine = IncidentEngine()
    incidents = engine.process_records_and_alerts(
        enriched, rule_alerts, beacon_alerts, exfil_alerts, ml_probs, is_synthetic=False
    )

    assert len(rule_alerts) == 0
    assert len(beacon_alerts) == 0
    assert len(exfil_alerts) == 0
    assert ml_probs[0] == 0.0
    assert len(incidents) == 0

