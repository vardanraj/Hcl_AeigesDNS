"""Incident Engine for AegisDNS.

Fuses rule scores, C2 beacon scores, exfiltration scores, and ML probabilities
into unified 0-100 risk scores. Groups repeated flags per (src_ip, base_domain)
into distinct incidents with severity ratings, evidence, and actionable recommendations.
"""

from typing import List, Dict, Any, Tuple
import hashlib
from backend.app.config import get_config, AppConfig
from backend.app.models.schemas import AlertDetail, Incident
from backend.app.analytics.detectors import is_allowlisted_domain


class IncidentEngine:
    """Fuses multi-detector outputs into grouped incidents with risk scores and recommendations."""

    def __init__(self, config: AppConfig = None):
        self.config = config or get_config()

    def generate_incident_id(self, src_ip: str, base_domain: str) -> str:
        """Create a deterministic unique incident ID string."""
        raw = f"{src_ip}:{base_domain}"
        digest = hashlib.md5(raw.encode("utf-8")).hexdigest()[:8]
        return f"INC-{digest.upper()}"

    def derive_recommended_action(self, triggered_rules: List[str], src_ip: str, base_domain: str) -> str:
        """Formulate a tailored remediation recommendation based on triggered threat categories."""
        actions = []
        if any("EXFILTRATION" in r for r in triggered_rules):
            actions.append(f"Block outbound DNS requests to root domain '{base_domain}' on perimeter firewalls.")
            actions.append(f"Isolate host {src_ip} and inspect endpoint for active malware or DNS tunneling agents.")

        if any("C2" in r or "BEACON" in r for r in triggered_rules):
            actions.append(f"Investigate host {src_ip} for persistent Command & Control (C2) beaconing.")
            actions.append(f"Add '{base_domain}' to DNS sinkhole / RPZ (Response Policy Zone).")

        if any("ENTROPY" in r or "LENGTH" in r or "HEX" in r for r in triggered_rules):
            actions.append(f"Inspect recent process logs on {src_ip} executing high-entropy DNS queries.")

        if not actions:
            actions.append(f"Monitor traffic from host {src_ip} towards '{base_domain}' for anomalous DNS query patterns.")

        return " ".join(actions)

    def process_records_and_alerts(
        self,
        records: List[Dict[str, Any]],
        rule_alerts: List[AlertDetail],
        beacon_alerts: List[AlertDetail],
        exfil_alerts: List[AlertDetail],
        ml_probabilities: List[float],
        is_synthetic: bool = True,
    ) -> List[Incident]:
        """Group alerts and records by (src_ip, base_domain) and construct fused Incident objects.

        Args:
            records: Enriched DNS query dictionaries.
            rule_alerts: AlertDetails from RuleBasedDetector.
            beacon_alerts: AlertDetails from C2BeaconDetector.
            exfil_alerts: AlertDetails from ExfiltrationDetector.
            ml_probabilities: Predicted ML anomaly probabilities parallel to records.
            is_synthetic: True if dataset is synthetic.

        Returns:
            List of fused Incident models.
        """
        # Group records by (src_ip, base_domain)
        groups: Dict[Tuple[str, str], Dict[str, Any]] = {}

        for idx, rec in enumerate(records):
            src_ip = rec.get("src_ip", "0.0.0.0")
            base_domain = rec.get("base_domain", "unknown")
            qname = rec.get("qname", "")
            if not base_domain or rec.get("is_allowlisted") or is_allowlisted_domain(base_domain) or is_allowlisted_domain(qname):
                continue

            key = (src_ip, base_domain)
            if key not in groups:
                groups[key] = {
                    "records": [],
                    "rule_alerts": [],
                    "beacon_alerts": [],
                    "exfil_alerts": [],
                    "ml_probs": [],
                    "first_seen": rec.get("timestamp", 0.0),
                    "last_seen": rec.get("timestamp", 0.0),
                }

            groups[key]["records"].append(rec)
            groups[key]["ml_probs"].append(ml_probabilities[idx] if idx < len(ml_probabilities) else 0.0)
            groups[key]["first_seen"] = min(groups[key]["first_seen"], rec.get("timestamp", 0.0))
            groups[key]["last_seen"] = max(groups[key]["last_seen"], rec.get("timestamp", 0.0))

        # Map alerts into groups
        for alert in rule_alerts:
            evidence = alert.evidence
            src_ip = evidence.get("src_ip")
            base_domain = evidence.get("base_domain")
            if not src_ip or not base_domain:
                # Fallback matching from record evidence if available
                subdomain = evidence.get("subdomain", "")
                if subdomain:
                    for (sip, bdom), data in groups.items():
                        if any(subdomain in r.get("qname", "") for r in data["records"]):
                            data["rule_alerts"].append(alert)
                            break
            else:
                key = (src_ip, base_domain)
                if key in groups:
                    groups[key]["rule_alerts"].append(alert)

        for alert in beacon_alerts:
            src_ip = alert.evidence.get("src_ip")
            base_domain = alert.evidence.get("base_domain")
            if src_ip and base_domain and (src_ip, base_domain) in groups:
                groups[(src_ip, base_domain)]["beacon_alerts"].append(alert)

        for alert in exfil_alerts:
            src_ip = alert.evidence.get("src_ip")
            base_domain = alert.evidence.get("base_domain")
            if src_ip and base_domain and (src_ip, base_domain) in groups:
                groups[(src_ip, base_domain)]["exfil_alerts"].append(alert)

        # Build Incident objects
        incidents: List[Incident] = []
        w = self.config.weights
        s_levels = self.config.severity_levels

        for (src_ip, base_domain), gdata in groups.items():
            # Calculate category sub-scores (0.0 to 1.0)
            r_score = max([a.score for a in gdata["rule_alerts"]], default=0.0)
            b_score = max([a.score for a in gdata["beacon_alerts"]], default=0.0)
            e_score = max([a.score for a in gdata["exfil_alerts"]], default=0.0)
            ml_score = max(gdata["ml_probs"], default=0.0) if gdata["ml_probs"] else 0.0

            # Calculate fused risk score (0.0 to 100.0)
            raw_risk = (
                (w.rule_weight * r_score)
                + (w.beacon_weight * b_score)
                + (w.exfil_weight * e_score)
                + (w.ml_weight * ml_score)
            ) * 100.0

            risk_score = round(min(100.0, max(0.0, raw_risk)), 1)

            # Assign Severity
            if risk_score >= s_levels.critical:
                severity = "Critical"
            elif risk_score >= s_levels.high:
                severity = "High"
            elif risk_score >= s_levels.medium:
                severity = "Medium"
            else:
                severity = "Low"

            # Filter out non-suspicious background noise if low risk & no rules triggered
            if risk_score < 15.0 and not gdata["rule_alerts"] and not gdata["beacon_alerts"] and not gdata["exfil_alerts"]:
                continue

            # Gather triggered rules
            triggered_rules = list(
                set(
                    [a.rule_name for a in gdata["rule_alerts"]]
                    + [a.rule_name for a in gdata["beacon_alerts"]]
                    + [a.rule_name for a in gdata["exfil_alerts"]]
                    + (["ML_ANOMALY_HIGH_PROB"] if ml_score > self.config.thresholds.ml_anomaly_threshold else [])
                )
            )

            # Top 5 evidence queries sorted by entropy
            sorted_recs = sorted(gdata["records"], key=lambda r: r.get("entropy", 0.0), reverse=True)
            evidence_queries = [
                {
                    "qname": r.get("qname"),
                    "qtype": r.get("qtype"),
                    "entropy": r.get("entropy"),
                    "subdomain_len": r.get("subdomain_len"),
                    "timestamp": r.get("timestamp"),
                }
                for r in sorted_recs[:5]
            ]

            recommended_action = self.derive_recommended_action(triggered_rules, src_ip, base_domain)
            inc_id = self.generate_incident_id(src_ip, base_domain)

            incidents.append(
                Incident(
                    incident_id=inc_id,
                    src_ip=src_ip,
                    base_domain=base_domain,
                    risk_score=risk_score,
                    severity=severity,
                    rule_score=round(r_score, 2),
                    beacon_score=round(b_score, 2),
                    exfiltration_score=round(e_score, 2),
                    ml_probability=round(ml_score, 4),
                    triggered_rules=triggered_rules,
                    query_count=len(gdata["records"]),
                    first_seen=gdata["first_seen"],
                    last_seen=gdata["last_seen"],
                    evidence_queries=evidence_queries,
                    recommended_action=recommended_action,
                    is_synthetic=is_synthetic,
                )
            )

        # Sort incidents descending by risk_score
        incidents.sort(key=lambda i: i.risk_score, reverse=True)
        return incidents
