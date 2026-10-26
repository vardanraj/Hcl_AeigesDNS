"""Live capture control endpoints and WebSocket /ws/live incident streamer."""

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, Depends
from pydantic import BaseModel
from typing import Optional, List, Dict, Any, Set
import asyncio
import json
import threading
import time

from backend.app.ingest.live_capture import live_sniffer
from backend.app.models.schemas import LiveCaptureStatus
from backend.app.analytics.feature_extractor import extract_dns_features
from backend.app.analytics.detectors import RuleBasedDetector
from backend.app.analytics.c2_beacon import C2BeaconDetector
from backend.app.analytics.exfiltration import ExfiltrationDetector
from backend.app.analytics.ml_classifier import MLAnomalyClassifier
from backend.app.analytics.incident_engine import IncidentEngine
from backend.app.analytics.timeline_helper import build_adaptive_timeline
from backend.app.config import get_config
from backend.app.core.session import verify_session_token
from backend.app.api.upload import analysis_store

router = APIRouter(prefix="/api/capture", tags=["capture"])

MAX_LIVE_RECORDS = 5000


# Active WebSocket connections manager
class LiveWebSocketManager:
    def __init__(self, max_connections: int = 10):
        self.active_connections: Set[WebSocket] = set()
        self.max_connections = max_connections

    async def connect(self, websocket: WebSocket) -> bool:
        if len(self.active_connections) >= self.max_connections:
            await websocket.close(code=1008, reason="Max WebSocket connections reached (limit 10)")
            return False
        await websocket.accept()
        self.active_connections.add(websocket)
        return True

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        to_remove = set()
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                to_remove.add(connection)
        for conn in to_remove:
            self.disconnect(conn)

ws_manager = LiveWebSocketManager()


class StartCaptureRequest(BaseModel):
    interface: Optional[str] = "default"


# Buffer to aggregate live packets into windows for incident processing
live_packet_buffer: List[Dict[str, Any]] = []
_buffer_lock = threading.Lock()

# Lock protecting writes to analysis_store from the live capture thread
_store_lock = threading.Lock()


def _rebuild_summary_from_store() -> Dict[str, Any]:
    """Recompute summary statistics from current analysis_store contents.

    Must be called while holding _store_lock.
    """
    records = analysis_store["records"]
    incidents = analysis_store["incidents"]

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for inc in incidents:
        sev = inc.get("severity", "Low")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    avg_ent = sum(r.get("entropy", 0.0) for r in records) / len(records) if records else 0.0
    # total_exfil_bytes is not easily reconstructable from stored incident dicts;
    # use the sum of exfiltration_score * query_count as a proxy kept at 0 for live data
    # (exact value is only available at analysis time via exfil_alerts)
    total_exfil = 0

    return {
        "total_queries": len(records),
        "total_incidents": len(incidents),
        "severity_breakdown": sev_counts,
        "total_exfil_bytes": total_exfil,
        "c2_beacon_count": sum(1 for inc in incidents if inc.get("beacon_score", 0.0) > 0.0),
        "avg_entropy": round(avg_ent, 2),
        "unique_domains_count": len(set(r.get("base_domain", "") for r in records if r.get("base_domain"))),
        "unique_src_ips_count": len(set(r.get("src_ip", "") for r in records)),
        "is_synthetic": False,
    }


def _live_packet_callback(record: Dict[str, Any]):
    """Callback executed for each packet captured by live sniffer."""
    global live_packet_buffer
    with _buffer_lock:
        if len(live_packet_buffer) >= 1000:
            live_packet_buffer.pop(0)  # drop oldest item
        live_packet_buffer.append(record)

        if len(live_packet_buffer) < 10:
            return
        batch = list(live_packet_buffer)
        live_packet_buffer.clear()

    config = get_config()
    enriched = [extract_dns_features(r) for r in batch]

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
        enriched, rule_alerts, beacon_alerts, exfil_alerts, ml_probs, is_synthetic=False
    )

    # --- Persist into analysis_store ---
    with _store_lock:
        # Append records, capped at MAX_LIVE_RECORDS (drop oldest)
        combined = analysis_store["records"] + enriched
        if len(combined) > MAX_LIVE_RECORDS:
            combined = combined[-MAX_LIVE_RECORDS:]
        analysis_store["records"] = combined

        # Merge incidents: update existing by incident_id or append new ones
        existing_by_id = {inc["incident_id"]: inc for inc in analysis_store["incidents"]}
        for inc in incidents:
            inc_dict = inc.model_dump()
            existing_by_id[inc_dict["incident_id"]] = inc_dict
        analysis_store["incidents"] = list(existing_by_id.values())

        # Recompute summary and timeline from updated store
        analysis_store["summary"] = _rebuild_summary_from_store()
        analysis_store["timeline"] = [
            t.model_dump() for t in build_adaptive_timeline(analysis_store["records"], config)
        ]
        analysis_store["last_updated"] = time.time()

    if incidents or rule_alerts:
        payload = {
            "type": "live_incidents",
            "timestamp": record.get("timestamp"),
            "packets_count": len(batch),
            "incidents": [inc.model_dump() for inc in incidents],
        }
        # Broadcast payload to active WebSocket clients
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                loop.create_task(ws_manager.broadcast(payload))
            else:
                loop.run_until_complete(ws_manager.broadcast(payload))
        except RuntimeError:
            try:
                asyncio.run(ws_manager.broadcast(payload))
            except Exception:
                pass


@router.post("/start", dependencies=[Depends(verify_session_token)])
async def start_live_capture(req: StartCaptureRequest = StartCaptureRequest()):
    """Start live network sniffer on port 53 with packet callback for live WebSocket stream.

    Resets analysis_store to empty state before starting so live results
    never mix with synthetic or PCAP data.
    """
    with _store_lock:
        analysis_store["records"] = []
        analysis_store["incidents"] = []
        analysis_store["summary"] = None
        analysis_store["timeline"] = []
        analysis_store["last_updated"] = 0

    success = live_sniffer.start_capture(interface=req.interface, callback=_live_packet_callback)
    status = live_sniffer.get_status()
    if not success:
        raise HTTPException(
            status_code=400,
            detail=status.get("error_message") or "Failed to start live packet capture."
        )
    return {"status": "started", "capture_info": status}


@router.post("/stop", dependencies=[Depends(verify_session_token)])
async def stop_live_capture():
    """Stop active live packet sniffer session."""
    live_sniffer.stop_capture()
    return {"status": "stopped", "capture_info": live_sniffer.get_status()}


@router.get("/status", response_model=LiveCaptureStatus)
async def get_capture_status():
    """Get current live sniffer status and packet counts."""
    return live_sniffer.get_status()
