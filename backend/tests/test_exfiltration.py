"""Unit tests for exfiltration.py subdomain diversity and payload volumetric detection."""

from backend.app.analytics.exfiltration import ExfiltrationDetector
from backend.app.utils.synthetic_gen import generate_synthetic_dns_records
from backend.app.analytics.feature_extractor import extract_dns_features


def test_exfiltration_detector():
    detector = ExfiltrationDetector()

    # Generate 20 unique high-length queries to badactor.org from 192.168.1.50
    records = []
    for i in range(20):
        records.append({
            "src_ip": "192.168.1.50",
            "base_domain": "badactor.org",
            "subdomain": f"payload_chunk_{i}_data_{i*100}",
            "qname_len": 50,
            "entropy": 4.1,
        })

    alerts = detector.detect_exfiltration(records)
    assert len(alerts) == 1
    assert alerts[0].rule_name == "DNS_DATA_EXFILTRATION"
    assert alerts[0].severity in {"HIGH", "CRITICAL"}


def test_exfiltration_fires_on_synthetic_exfil_families():
    """Assert exfiltration detector fires on synthetic exfiltration attack families."""
    records = generate_synthetic_dns_records(num_records=300, tunnel_ratio=0.30)
    enriched = [extract_dns_features(r) for r in records]

    detector = ExfiltrationDetector()
    alerts = detector.detect_exfiltration(enriched)

    assert len(alerts) >= 3
    domains_alerted = set(a.evidence["base_domain"] for a in alerts)
    assert "covert-epsilon.io" in domains_alerted or "exfil-beta.com" in domains_alerted or "beacon-delta.info" in domains_alerted
