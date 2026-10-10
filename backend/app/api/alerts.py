"""Incident alerts, investigation, summary, and export endpoints."""

from fastapi import APIRouter, Query, Response, HTTPException
from fastapi.responses import StreamingResponse
from typing import Optional, List, Dict, Any
import json
import csv
import io

from backend.app.api.upload import analysis_store
from backend.app.utils.synthetic_gen import generate_synthetic_dns_records
from backend.app.analytics.feature_extractor import extract_dns_features
from backend.app.analytics.detectors import RuleBasedDetector
from backend.app.analytics.c2_beacon import C2BeaconDetector
from backend.app.analytics.exfiltration import ExfiltrationDetector
from backend.app.analytics.ml_classifier import MLAnomalyClassifier
from backend.app.analytics.incident_engine import IncidentEngine
from backend.app.config import get_config

router = APIRouter(prefix="/api", tags=["alerts"])


def _ensure_active_dataset():
    """Ensure analysis store has data; if empty, load synthetic demo dataset."""
    if not analysis_store["records"]:
        config = get_config()
        raw_recs = generate_synthetic_dns_records(num_records=150, tunnel_ratio=0.25)
        enriched = [extract_dns_features(r) for r in raw_recs]

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
        timeline = [t.model_dump() for t in build_adaptive_timeline(enriched, config)]

        analysis_store["records"] = enriched
        analysis_store["incidents"] = [inc.model_dump() for inc in incidents]
        analysis_store["summary"] = summary
        analysis_store["timeline"] = timeline


@router.get("/alerts")
async def get_alerts(
    severity: Optional[str] = None,
    domain: Optional[str] = None,
    src_ip: Optional[str] = None,
):
    """Retrieve list of incident alerts with optional filtering."""
    _ensure_active_dataset()
    incidents = analysis_store["incidents"]

    filtered = incidents
    if severity:
        filtered = [i for i in filtered if i["severity"].lower() == severity.lower()]
    if domain:
        filtered = [i for i in filtered if domain.lower() in i["base_domain"].lower()]
    if src_ip:
        filtered = [i for i in filtered if src_ip in i["src_ip"]]

    return {"status": "success", "incidents": filtered, "count": len(filtered)}


@router.get("/summary")
async def get_summary():
    """Retrieve aggregate summary statistics."""
    _ensure_active_dataset()
    return analysis_store["summary"]


@router.get("/timeline")
async def get_timeline():
    """Retrieve time-series chart data."""
    _ensure_active_dataset()
    return analysis_store["timeline"]


@router.get("/investigate/{domain}")
async def investigate_domain(domain: str):
    """Retrieve forensic breakdown for a specific root domain."""
    _ensure_active_dataset()
    records = [r for r in analysis_store["records"] if r.get("base_domain", "").lower() == domain.lower()]
    incidents = [i for i in analysis_store["incidents"] if i.get("base_domain", "").lower() == domain.lower()]

    if not records and not incidents:
        raise HTTPException(status_code=404, detail=f"No forensic records found for domain '{domain}'.")

    return {
        "domain": domain,
        "query_count": len(records),
        "incidents": incidents,
        "queries": records[:50],  # Top 50 records for deep inspection
    }


@router.get("/incidents/export")
async def export_incidents(format: str = Query("json", pattern="^(json|csv)$")):
    """Export incidents in JSON or CSV format for report download."""
    _ensure_active_dataset()
    incidents = analysis_store["incidents"]

    if format == "json":
        data_str = json.dumps(incidents, indent=2)
        return Response(
            content=data_str,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=aegisdns_incidents.json"},
        )
    elif format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Incident_ID", "Source_IP", "Base_Domain", "Risk_Score", "Severity",
            "Triggered_Rules", "Query_Count", "Recommended_Action", "Is_Synthetic"
        ])
        for inc in incidents:
            writer.writerow([
                inc.get("incident_id"),
                inc.get("src_ip"),
                inc.get("base_domain"),
                inc.get("risk_score"),
                inc.get("severity"),
                "; ".join(inc.get("triggered_rules", [])),
                inc.get("query_count"),
                inc.get("recommended_action"),
                inc.get("is_synthetic"),
            ])
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode("utf-8")),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=aegisdns_incidents.csv"},
        )


@router.get("/evaluation")
async def get_evaluation_results():
    """Return 5-seed Leave-One-Attack-Family-Out evaluation metrics from seed_summary.csv."""
    from backend.app.config import PROJECT_ROOT
    csv_path = PROJECT_ROOT / "reports" / "seed_summary.csv"

    if not csv_path.exists():
        raise HTTPException(status_code=404, detail="Evaluation results report not found.")

    metrics = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            metrics.append({
                "detector": row["detector"],
                "precision_mean": float(row["precision_mean"]),
                "precision_std": float(row["precision_std"]),
                "recall_mean": float(row["recall_mean"]),
                "recall_std": float(row["recall_std"]),
                "f1_mean": float(row["f1_mean"]),
                "f1_std": float(row["f1_std"]),
                "auc_mean": float(row["auc_mean"]),
                "auc_std": float(row["auc_std"]),
                "fp_1k_mean": float(row["fp_1k_mean"]),
                "fp_1k_std": float(row["fp_1k_std"]),
            })

    return {"status": "success", "metrics": metrics}
