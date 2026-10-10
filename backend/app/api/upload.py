"""PCAP upload and analysis endpoint with security checks and immediate cleanup.

Enforces 50 MB upload limits, validates PCAP magic bytes, extracts features,
runs detection engines, and cleans up temporary files post-analysis.
"""

from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from pathlib import Path
import tempfile
import os
import shutil
import time

from backend.app.config import get_config
from backend.app.ingest.pcap_parser import validate_pcap_magic_bytes, parse_pcap_file
from backend.app.analytics.feature_extractor import extract_dns_features
from backend.app.analytics.detectors import RuleBasedDetector
from backend.app.analytics.c2_beacon import C2BeaconDetector
from backend.app.analytics.exfiltration import ExfiltrationDetector
from backend.app.analytics.ml_classifier import MLAnomalyClassifier
from backend.app.analytics.incident_engine import IncidentEngine
from backend.app.models.schemas import Incident, AnalysisSummary, TimelineDataPoint

router = APIRouter(prefix="/api/pcap", tags=["pcap"])

# In-memory session store for current analysis results
analysis_store = {
    "records": [],
    "incidents": [],
    "summary": None,
    "timeline": [],
    "last_updated": 0,
}


@router.post("/upload")
async def upload_pcap(file: UploadFile = File(...)):
    """Upload and analyze PCAP / PCAPNG packet capture file."""
    config = get_config()
    max_bytes = config.server.max_upload_size_mb * 1024 * 1024

    # 1. Read file size check
    file_bytes = await file.read()
    if len(file_bytes) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File size exceeds maximum limit of {config.server.max_upload_size_mb} MB."
        )

    # 2. Write temp file safely for analysis
    temp_dir = Path(tempfile.gettempdir()) / "aegisdns_uploads"
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_file_path = temp_dir / f"upload_{int(time.time())}_{file.filename}"

    try:
        with open(temp_file_path, "wb") as f:
            f.write(file_bytes)

        # 3. Magic Bytes Header Check
        if not validate_pcap_magic_bytes(temp_file_path):
            raise HTTPException(
                status_code=400,
                detail="Invalid file header. Uploaded file is not a valid PCAP or PCAPNG packet capture."
            )

        # 4. Parse PCAP packets
        raw_records = parse_pcap_file(temp_file_path, is_synthetic=False)
        if not raw_records:
            raise HTTPException(
                status_code=400,
                detail="No DNS query packets found on port 53 in the uploaded PCAP file."
            )

        # Detect synthetic generator marker or synthetic domain signatures
        from backend.app.utils.synthetic_gen import TUNNEL_BASE_DOMAINS
        is_pcap_synthetic = any(
            r.get("qname") == "aegisdns-synthetic-marker.local" or r.get("base_domain") in TUNNEL_BASE_DOMAINS
            for r in raw_records
        )

        # Strip internal synthetic marker packet if present
        raw_records = [r for r in raw_records if r.get("qname") != "aegisdns-synthetic-marker.local"]
        for r in raw_records:
            r["is_synthetic"] = is_pcap_synthetic

        if not raw_records:
            raise HTTPException(
                status_code=400,
                detail="No DNS query packets found on port 53 in the uploaded PCAP file."
            )

        # 5. Extract features
        enriched_records = [extract_dns_features(r) for r in raw_records]

        # 6. Run Detectors
        rule_detector = RuleBasedDetector(config.thresholds)
        beacon_detector = C2BeaconDetector(config.thresholds)
        exfil_detector = ExfiltrationDetector(config.thresholds)
        ml_classifier = MLAnomalyClassifier()

        rule_alerts = rule_detector.evaluate_batch(enriched_records)
        beacon_alerts = beacon_detector.detect_beacons(enriched_records)
        exfil_alerts = exfil_detector.detect_exfiltration(enriched_records)
        ml_probs = ml_classifier.predict_batch(enriched_records)

        # 7. Fuse Incidents
        engine = IncidentEngine(config)
        incidents = engine.process_records_and_alerts(
            enriched_records, rule_alerts, beacon_alerts, exfil_alerts, ml_probs, is_synthetic=is_pcap_synthetic
        )

        # 8. Compute Summary Statistics
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for inc in incidents:
            sev_counts[inc.severity] = sev_counts.get(inc.severity, 0) + 1

        total_exfil = sum(
            a.evidence.get("total_payload_bytes", 0) for a in exfil_alerts
        )
        avg_ent = (
            sum(r["entropy"] for r in enriched_records) / len(enriched_records)
            if enriched_records else 0.0
        )

        summary = AnalysisSummary(
            total_queries=len(enriched_records),
            total_incidents=len(incidents),
            severity_breakdown=sev_counts,
            total_exfil_bytes=total_exfil,
            c2_beacon_count=len(beacon_alerts),
            avg_entropy=round(avg_ent, 2),
            unique_domains_count=len(set(r["base_domain"] for r in enriched_records if r["base_domain"])),
            unique_src_ips_count=len(set(r["src_ip"] for r in enriched_records)),
            is_synthetic=is_pcap_synthetic,
        )

        # 9. Build Adaptive Timeline Data Points
        from backend.app.analytics.timeline_helper import build_adaptive_timeline
        timeline = build_adaptive_timeline(enriched_records, config)

        # Update Session Store
        analysis_store["records"] = enriched_records
        analysis_store["incidents"] = [inc.model_dump() for inc in incidents]
        analysis_store["summary"] = summary.model_dump()
        analysis_store["timeline"] = [t.model_dump() for t in timeline]
        analysis_store["last_updated"] = time.time()

        return {
            "status": "success",
            "filename": file.filename,
            "synthetic": is_pcap_synthetic,
            "summary": summary,
            "incidents_count": len(incidents),
            "total_queries": len(enriched_records),
        }

    finally:
        # Security Requirement 5: Delete temp files immediately after analysis
        if temp_file_path.exists():
            try:
                os.remove(temp_file_path)
            except Exception:
                pass
