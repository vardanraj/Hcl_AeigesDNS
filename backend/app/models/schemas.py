"""Pydantic schemas for request payloads, analysis results, and incidents."""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class DNSQueryRecord(BaseModel):
    """Normalized raw DNS query record with calculated feature attributes."""
    timestamp: float
    datetime_str: Optional[str] = None
    src_ip: str
    dst_ip: str
    qname: str
    qtype: str
    qclass: str = "IN"
    rcode: str = "NOERROR"
    payload_len: int = 0
    subdomain: str = ""
    base_domain: str = ""
    entropy: float = 0.0
    qname_len: int = 0
    subdomain_len: int = 0
    digit_ratio: float = 0.0
    hex_ratio: float = 0.0
    uppercase_ratio: float = 0.0
    is_synthetic: bool = True


class AlertDetail(BaseModel):
    """Detailed record of a single detector flag."""
    detector_type: str  # rule, c2_beacon, exfiltration, ml
    rule_name: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    score: float
    evidence: Dict[str, Any] = Field(default_factory=dict)


class Incident(BaseModel):
    """Fused incident representing grouped alerts per (src_ip, base_domain)."""
    incident_id: str
    src_ip: str
    base_domain: str
    risk_score: float  # 0.0 to 100.0
    severity: str  # Low, Medium, High, Critical
    rule_score: float = 0.0
    beacon_score: float = 0.0
    exfiltration_score: float = 0.0
    ml_probability: float = 0.0
    triggered_rules: List[str] = Field(default_factory=list)
    query_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    evidence_queries: List[Dict[str, Any]] = Field(default_factory=list)
    recommended_action: str = ""
    is_synthetic: bool = True


class AnalysisSummary(BaseModel):
    """Aggregate summary statistics for a PCAP or live stream session."""
    total_queries: int = 0
    total_incidents: int = 0
    severity_breakdown: Dict[str, int] = Field(
        default_factory=lambda: {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    )
    total_exfil_bytes: int = 0
    c2_beacon_count: int = 0
    avg_entropy: float = 0.0
    unique_domains_count: int = 0
    unique_src_ips_count: int = 0
    is_synthetic: bool = True


class TimelineDataPoint(BaseModel):
    """Time-series entry for dashboard charts."""
    timestamp: str
    total_queries: int
    anomalous_queries: int
    critical_incidents: int = 0


class LiveCaptureStatus(BaseModel):
    """Status payload for live network capture on port 53."""
    is_capturing: bool = False
    interface: str = "default"
    packets_captured: int = 0
    incidents_detected: int = 0
    start_time: Optional[float] = None
    npcap_available: bool = True
    error_message: Optional[str] = None
