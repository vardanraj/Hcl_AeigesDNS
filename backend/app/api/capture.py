"""Live capture control endpoints and WebSocket /ws/live incident streamer."""

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, Depends
from pydantic import BaseModel
from typing import Optional, List, Dict, Any, Set
import asyncio
import json
import threading

from backend.app.ingest.live_capture import live_sniffer
from backend.app.models.schemas import LiveCaptureStatus
from backend.app.analytics.feature_extractor import extract_dns_features
from backend.app.analytics.detectors import RuleBasedDetector
from backend.app.analytics.c2_beacon import C2BeaconDetector
from backend.app.analytics.exfiltration import ExfiltrationDetector
from backend.app.analytics.ml_classifier import MLAnomalyClassifier
from backend.app.analytics.incident_engine import IncidentEngine
from backend.app.config import get_config
from backend.app.core.session import verify_session_token

router = APIRouter(prefix="/api/capture", tags=["capture"])


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
    """Start live network sniffer on port 53 with packet callback for live WebSocket stream."""
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
