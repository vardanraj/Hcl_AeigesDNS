"""Synthetic dataset generator API endpoint."""

from fastapi import APIRouter, Depends
import time
from backend.app.core.session import verify_session_token
from backend.app.utils.synthetic_gen import generate_synthetic_dns_records
from backend.app.analytics.feature_extractor import extract_dns_features
from backend.app.analytics.detectors import RuleBasedDetector
from backend.app.analytics.c2_beacon import C2BeaconDetector
from backend.app.analytics.exfiltration import ExfiltrationDetector
from backend.app.analytics.ml_classifier import MLAnomalyClassifier
from backend.app.analytics.incident_engine import IncidentEngine
from backend.app.api.upload import analysis_store
from backend.app.config import get_config

router = APIRouter(prefix="/api/synthetic", tags=["synthetic"])


@router.post("/generate", dependencies=[Depends(verify_session_token)])
async def generate_synthetic_traffic(num_records: int = 200, tunnel_ratio: float = 0.25):
    """Trigger generation of synthetic benign and tunneled DNS queries."""
    config = get_config()
    raw_records = generate_synthetic_dns_records(num_records=num_records, tunnel_ratio=tunnel_ratio)
    enriched = [extract_dns_features(r) for r in raw_records]

    rule_detector = RuleBasedDetector(config.thresholds)
    beacon_detector = C2BeaconDetector(config.thresholds)
    exfil_detector = ExfiltrationDetector(config.thresholds)
    ml_classifier = MLAnomalyClassifier()

    rule_alerts = rule_detector.evaluate_batch(enriched)
    beacon_alerts = beacon_detector.detect_beacons(enriched)
    exfil_alerts = exfil_detector.detect_exfiltration(enriched)
    ml_probs = ml_classifier.predict_batch(enriched)

    engine = IncidentEngine(config)
    incidents = engine.process_records_and_alerts(
        enriched, rule_alerts, beacon_alerts, exfil_alerts, ml_probs, is_synthetic=True
    )

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for inc in incidents:
        sev_counts[inc.severity] = sev_counts.get(inc.severity, 0) + 1

    total_exfil = sum(a.evidence.get("total_payload_bytes", 0) for a in exfil_alerts)
    avg_ent = sum(r["entropy"] for r in enriched) / len(enriched) if enriched else 0.0

    summary = {
        "total_queries": len(enriched),
        "total_incidents": len(incidents),
        "severity_breakdown": sev_counts,
        "total_exfil_bytes": total_exfil,
        "c2_beacon_count": len(beacon_alerts),
        "avg_entropy": round(avg_ent, 2),
        "unique_domains_count": len(set(r["base_domain"] for r in enriched if r["base_domain"])),
        "unique_src_ips_count": len(set(r["src_ip"] for r in enriched)),
        "is_synthetic": True,
    }

    from backend.app.analytics.timeline_helper import build_adaptive_timeline
    timeline = build_adaptive_timeline(enriched, config)

    # Update global analysis store
    analysis_store["records"] = enriched
    analysis_store["incidents"] = [inc.model_dump() for inc in incidents]
    analysis_store["summary"] = summary
    analysis_store["timeline"] = [t.model_dump() for t in timeline]
    analysis_store["last_updated"] = time.time()

    return {
        "status": "success",
        "message": f"Generated {num_records} synthetic records (labeled synthetic).",
        "incidents_count": len(incidents),
        "summary": summary,
    }
