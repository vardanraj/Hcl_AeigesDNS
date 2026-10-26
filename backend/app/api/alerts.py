"""Incident alerts, investigation, summary, and export endpoints."""

from fastapi import APIRouter, Query, Response, HTTPException, Depends
from fastapi.responses import StreamingResponse
from typing import Optional, List, Dict, Any
import json
import csv
import io
import time

from backend.app.core.session import verify_session_token
from backend.app.api.upload import analysis_store

router = APIRouter(prefix="/api", tags=["alerts"])

_EMPTY_SUMMARY = {
    "total_queries": 0,
    "total_incidents": 0,
    "severity_breakdown": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
    "total_exfil_bytes": 0,
    "c2_beacon_count": 0,
    "avg_entropy": 0.0,
    "unique_domains_count": 0,
    "unique_src_ips_count": 0,
    "is_synthetic": False,
}


@router.get("/alerts")
async def get_alerts(
    severity: Optional[str] = None,
    domain: Optional[str] = None,
    src_ip: Optional[str] = None,
):
    """Retrieve list of incident alerts with optional filtering.

    Returns an empty list when no data has been loaded yet.
    """
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
    """Retrieve aggregate summary statistics.

    Returns zero-state summary when no data has been loaded yet.
    """
    return analysis_store["summary"] or _EMPTY_SUMMARY


@router.get("/timeline")
async def get_timeline():
    """Retrieve time-series chart data.

    Returns an empty list when no data has been loaded yet.
    """
    return analysis_store["timeline"]


@router.get("/investigate/{domain}")
async def investigate_domain(domain: str):
    """Retrieve forensic breakdown for a specific root domain."""
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


def sanitize_csv_cell(value: Any) -> Any:
    """Sanitize CSV cell to prevent formula injection (=, +, -, @, \\t, \\r)."""
    if value is None:
        return ""
    val_str = str(value)
    if val_str.startswith(("=", "+", "-", "@", "\t", "\r")):
        return f"'{val_str}"
    return value


@router.get("/incidents/export", dependencies=[Depends(verify_session_token)])
async def export_incidents(format: str = Query("json", pattern="^(json|csv)$")):
    """Export incidents in JSON or CSV format for report download."""
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
                sanitize_csv_cell(inc.get("incident_id")),
                sanitize_csv_cell(inc.get("src_ip")),
                sanitize_csv_cell(inc.get("base_domain")),
                sanitize_csv_cell(inc.get("risk_score")),
                sanitize_csv_cell(inc.get("severity")),
                sanitize_csv_cell("; ".join(inc.get("triggered_rules", []))),
                sanitize_csv_cell(inc.get("query_count")),
                sanitize_csv_cell(inc.get("recommended_action")),
                sanitize_csv_cell(inc.get("is_synthetic")),
            ])
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode("utf-8")),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=aegisdns_incidents.csv"},
        )


@router.post("/data/clear", dependencies=[Depends(verify_session_token)])
async def clear_data():
    """Reset the in-memory analysis store to empty state.

    Clears all records, incidents, summary, and timeline data.
    Does not affect models, config, or evaluation results.
    """
    analysis_store["records"] = []
    analysis_store["incidents"] = []
    analysis_store["summary"] = None
    analysis_store["timeline"] = []
    analysis_store["last_updated"] = 0
    return {"status": "cleared", "message": "Analysis store reset to empty state."}


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
