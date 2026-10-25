"""Integration tests for FastAPI endpoints, session tokens, WebSocket live streaming, and synthetic detection."""

import pytest
import time
from unittest.mock import patch
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.utils.synthetic_gen import generate_synthetic_pcap, generate_synthetic_dns_records
from backend.app.config import get_config
from backend.app.api.capture import _live_packet_callback

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["system"] == "AegisDNS"
    assert data["status"] == "online"


def test_session_endpoint_and_token_protection():
    """Verify session token generation and authorization enforcement on control endpoints."""
    # Retrieve session token
    res = client.get("/api/session")
    assert res.status_code == 200
    token = res.json()["token"]
    assert token and len(token) > 10

    # Test POST /api/capture/start without token -> 401
    start_no_token = client.post("/api/capture/start", json={"interface": "default"})
    assert start_no_token.status_code == 401

    # Test POST /api/capture/stop without token -> 401
    stop_no_token = client.post("/api/capture/stop")
    assert stop_no_token.status_code == 401

    # Test PUT /api/config without token -> 401
    cfg = get_config().thresholds.model_dump()
    cfg_no_token = client.put("/api/config", json=cfg)
    assert cfg_no_token.status_code == 401

    # Test PUT /api/config with valid token header -> 200
    headers = {"X-AegisDNS-Token": token}
    cfg_with_token = client.put("/api/config", json=cfg, headers=headers)
    assert cfg_with_token.status_code == 200


def test_config_get_endpoint():
    get_res = client.get("/api/config")
    assert get_res.status_code == 200
    cfg = get_res.json()
    assert "thresholds" in cfg
    assert cfg["server"]["host"] == "127.0.0.1"


def test_config_put_validation_bad_values():
    """Verify that updating config with invalid values returns 422 Unprocessable Entity."""
    token = client.get("/api/session").json()["token"]
    headers = {"X-AegisDNS-Token": token}

    current_cfg = get_config().thresholds.model_dump()
    # Modify entropy_threshold out of range (ge=0.0, le=8.0)
    bad_cfg = dict(current_cfg)
    bad_cfg["entropy_threshold"] = 99.0

    res = client.put("/api/config", json=bad_cfg, headers=headers)
    assert res.status_code == 422

    # Modify subdomain_length_threshold to negative value (ge=1)
    bad_cfg_2 = dict(current_cfg)
    bad_cfg_2["subdomain_length_threshold"] = -10
    res_2 = client.put("/api/config", json=bad_cfg_2, headers=headers)
    assert res_2.status_code == 422


def test_config_reset_endpoint():
    """Verify resetting runtime config back to read-only validated defaults."""
    token = client.get("/api/session").json()["token"]
    headers = {"X-AegisDNS-Token": token}

    res = client.post("/api/config/reset", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "config" in data
    assert data["config"]["thresholds"]["ml_anomaly_threshold"] == 0.15
    assert data["config"]["thresholds"]["fused_threshold"] == 0.50


def test_synthetic_generate_endpoint():
    token = client.get("/api/session").json()["token"]
    res = client.post("/api/synthetic/generate?num_records=50&tunnel_ratio=0.25", headers={"X-AegisDNS-Token": token})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["summary"]["is_synthetic"] is True


def test_alerts_summary_timeline_investigate_endpoints():
    token = client.get("/api/session").json()["token"]
    client.post("/api/synthetic/generate?num_records=50", headers={"X-AegisDNS-Token": token})

    alerts_res = client.get("/api/alerts")
    assert alerts_res.status_code == 200
    assert "incidents" in alerts_res.json()

    filtered_res = client.get("/api/alerts?severity=High")
    assert filtered_res.status_code == 200

def test_adaptive_timeline_multiple_buckets():
    """Verify adaptive timeline bucketer creates multiple time buckets for spread timestamps."""
    from backend.app.analytics.timeline_helper import build_adaptive_timeline
    config = get_config()

    # Generate 50 records spread over 120 seconds
    records = []
    base_ts = 1700000000.0
    for i in range(50):
        records.append({
            "timestamp": base_ts + (i * 2.4),
            "entropy": 4.0 if i % 5 == 0 else 2.5,
            "subdomain_len": 40 if i % 5 == 0 else 10,
            "qtype": "TXT" if i % 5 == 0 else "A",
        })

    timeline = build_adaptive_timeline(records, config)
    assert len(timeline) >= 4
    assert sum(t.total_queries for t in timeline) == 50
    assert sum(t.anomalous_queries for t in timeline) > 0

    inv_404 = client.get("/api/investigate/nonexistentdomain1234.org")
    assert inv_404.status_code == 404


def test_incidents_export_json_and_csv():
    token = client.get("/api/session").json()["token"]
    headers = {"X-AegisDNS-Token": token}
    client.post("/api/synthetic/generate?num_records=50", headers=headers)

    json_res = client.get("/api/incidents/export?format=json", headers=headers)
    assert json_res.status_code == 200
    assert json_res.headers["content-type"].startswith("application/json")

    csv_res = client.get("/api/incidents/export?format=csv", headers=headers)
    assert csv_res.status_code == 200
    assert csv_res.headers["content-type"].startswith("text/csv")


def test_pcap_upload_non_pcap_header(tmp_path):
    token = client.get("/api/session").json()["token"]
    headers = {"X-AegisDNS-Token": token}
    invalid_file = tmp_path / "bad.pcap"
    invalid_file.write_bytes(b"INVALID_HEADER_DATA_123456789")

    with open(invalid_file, "rb") as f:
        res = client.post(
            "/api/pcap/upload",
            files={"file": ("bad.pcap", f, "application/octet-stream")},
            headers=headers
        )

    assert res.status_code == 400
    assert "Invalid file header" in res.json()["detail"]


def test_pcap_upload_oversized():
    token = client.get("/api/session").json()["token"]
    headers = {"X-AegisDNS-Token": token}
    huge_bytes = b"X" * (50 * 1024 * 1024 + 1024)

    res = client.post(
        "/api/pcap/upload",
        files={"file": ("huge.pcap", huge_bytes, "application/octet-stream")},
        headers=headers
    )

    assert res.status_code == 413
    assert "File size exceeds maximum limit" in res.json()["detail"]


def test_pcap_upload_valid_synthetic(tmp_path):
    token = client.get("/api/session").json()["token"]
    headers = {"X-AegisDNS-Token": token}
    valid_pcap = tmp_path / "valid.pcap"
    generate_synthetic_pcap(valid_pcap, num_records=30)

    with open(valid_pcap, "rb") as f:
        res = client.post(
            "/api/pcap/upload",
            files={"file": ("valid.pcap", f, "application/octet-stream")},
            headers=headers
        )

    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["synthetic"] is True
    assert data["summary"]["is_synthetic"] is True
    assert data["total_queries"] > 0


def test_websocket_origin_validation():
    """Verify WebSocket /ws/live origin validation allowed vs disallowed vs missing."""
    token = client.get("/api/session").json()["token"]

    # Allowed origin with token auth succeeds
    with client.websocket_connect("/ws/live", headers={"Origin": "http://localhost:5173"}) as ws:
        ws.send_json({"token": token})
        ws.send_text("ping")

    # Disallowed origin -> closed with code 1008
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/live", headers={"Origin": "http://malicious-domain.com"}) as ws:
            ws.send_json({"token": token})

    # Missing origin -> closed with code 1008
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/live") as ws:
            ws.send_json({"token": token})


def test_live_incident_push_to_websocket():
    """Verify injecting live packets pushes detected incidents directly to /ws/live clients."""
    token = client.get("/api/session").json()["token"]
    with client.websocket_connect("/ws/live", headers={"Origin": "http://localhost:5173"}) as ws:
        ws.send_json({"token": token})

        # Generate 10 synthetic tunneled packet records
        synth_recs = generate_synthetic_dns_records(num_records=12, tunnel_ratio=0.80)

        # Feed batch into live packet callback pipeline
        for r in synth_recs:
            _live_packet_callback(r)

        # Assert WebSocket receives incident broadcast payload
        data = ws.receive_json()
        assert data["type"] == "live_incidents"
        assert "incidents" in data
        assert len(data["incidents"]) > 0


def test_live_capture_status_and_control():
    token = client.get("/api/session").json()["token"]
    headers = {"X-AegisDNS-Token": token}

    status_res = client.get("/api/capture/status")
    assert status_res.status_code == 200
    status = status_res.json()
    assert "is_capturing" in status
    assert "npcap_available" in status

    stop_res = client.post("/api/capture/stop", headers=headers)
    assert stop_res.status_code == 200
    assert stop_res.json()["status"] == "stopped"


def test_live_capture_start_when_npcap_missing():
    token = client.get("/api/session").json()["token"]
    headers = {"X-AegisDNS-Token": token}

    with patch("backend.app.ingest.live_capture.live_sniffer.check_npcap_availability", return_value=False):
        res = client.post("/api/capture/start", json={"interface": "default"}, headers=headers)
        assert res.status_code == 400
        assert "Npcap" in res.json()["detail"] or "Failed" in res.json()["detail"]


# ==============================================================================
# Security Tests
# ==============================================================================

def test_security_missing_token_on_upload_returns_401(tmp_path):
    """Verify POST /api/pcap/upload without X-AegisDNS-Token returns 401."""
    dummy_file = tmp_path / "dummy.pcap"
    dummy_file.write_bytes(b"\xa1\xb2\xc3\xd4" + b"\x00" * 30)
    with open(dummy_file, "rb") as f:
        res = client.post("/api/pcap/upload", files={"file": ("dummy.pcap", f, "application/octet-stream")})
    assert res.status_code == 401
    assert "Invalid or missing session token" in res.json()["detail"]


def test_security_missing_token_on_synthetic_generate_returns_401():
    """Verify POST /api/synthetic/generate without X-AegisDNS-Token returns 401."""
    res = client.post("/api/synthetic/generate?num_records=10")
    assert res.status_code == 401
    assert "Invalid or missing session token" in res.json()["detail"]


def test_security_missing_token_on_export_returns_401():
    """Verify GET /api/incidents/export without X-AegisDNS-Token returns 401."""
    res = client.get("/api/incidents/export?format=csv")
    assert res.status_code == 401
    assert "Invalid or missing session token" in res.json()["detail"]


def test_security_websocket_invalid_token_rejected():
    """Verify /ws/live closes connection when supplied token is invalid."""
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/live", headers={"Origin": "http://localhost:5173"}) as ws:
            ws.send_json({"token": "WRONG_TOKEN_VALUE_XYZ"})
            ws.receive_text()


def test_security_upload_path_traversal_filename_safe(tmp_path):
    """Verify filenames with path traversal characters do not write outside the upload directory."""
    token = client.get("/api/session").json()["token"]
    headers = {"X-AegisDNS-Token": token}
    valid_pcap = tmp_path / "trav_test.pcap"
    generate_synthetic_pcap(valid_pcap, num_records=10)

    with open(valid_pcap, "rb") as f:
        res = client.post(
            "/api/pcap/upload",
            files={"file": ("../../escape_attempt.pcap", f, "application/octet-stream")},
            headers=headers
        )
    assert res.status_code == 200
    assert not (tmp_path.parent / "escape_attempt.pcap").exists()


def test_security_csv_export_sanitizes_formula_injection():
    """Verify sanitize_csv_cell escapes =, +, -, @, \\t, \\r to prevent spreadsheet formula injection."""
    from backend.app.api.alerts import sanitize_csv_cell
    assert sanitize_csv_cell("=CMD|' /C calc'!A0") == "'=CMD|' /C calc'!A0"
    assert sanitize_csv_cell("+12345") == "'+12345"
    assert sanitize_csv_cell("-SOMEPAYLOAD") == "'-SOMEPAYLOAD"
    assert sanitize_csv_cell("@SUM(1,2)") == "'@SUM(1,2)"
    assert sanitize_csv_cell("regular_domain.com") == "regular_domain.com"
    assert sanitize_csv_cell(123) == 123


def test_security_pcap_max_packets_exceeded_error():
    """Verify PCAP exceeding MAX_PARSE_PACKETS raises clear ValueError."""
    from backend.app.ingest.pcap_parser import parse_pcap_file, MAX_PARSE_PACKETS
    with patch("backend.app.ingest.pcap_parser.rdpcap") as mock_rdpcap:
        mock_rdpcap.return_value = [None] * (MAX_PARSE_PACKETS + 1)
        with patch("backend.app.ingest.pcap_parser.validate_pcap_magic_bytes", return_value=True):
            with pytest.raises(ValueError) as exc:
                parse_pcap_file("dummy_path.pcap")
            assert "exceeds maximum allowed limit" in str(exc.value)

