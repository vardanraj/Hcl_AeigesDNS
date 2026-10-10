"""Exfiltration Detector using volumetric analysis and subdomain cardinality metrics.

Detects covert data exfiltration by evaluating unique subdomain diversity
and aggregate outbound query payload volume per root domain.
"""

from typing import List, Dict, Any, Tuple
from backend.app.config import get_config, ThresholdsConfig
from backend.app.models.schemas import AlertDetail
from backend.app.analytics.detectors import is_allowlisted_domain


class ExfiltrationDetector:
    """Detects DNS data exfiltration based on payload size and subdomain cardinality."""

    def __init__(self, thresholds: ThresholdsConfig = None):
        self.thresholds = thresholds or get_config().thresholds

    def detect_exfiltration(self, records: List[Dict[str, Any]]) -> List[AlertDetail]:
        """Analyze batch of records for high subdomain cardinality and payload volume exfil.

        Args:
            records: List of enriched DNS query dictionaries.

        Returns:
            List of exfiltration AlertDetail objects.
        """
        grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}

        for rec in records:
            src_ip = rec.get("src_ip", "0.0.0.0")
            base_domain = rec.get("base_domain", "")
            qname = rec.get("qname", "")
            subdomain = rec.get("subdomain", "")
            qname_len = rec.get("qname_len", 0)

            if not base_domain or rec.get("is_allowlisted") or is_allowlisted_domain(base_domain) or is_allowlisted_domain(qname):
                continue

            key = (src_ip, base_domain)
            if key not in grouped:
                grouped[key] = {
                    "unique_subdomains": set(),
                    "total_bytes": 0,
                    "query_count": 0,
                    "high_entropy_count": 0,
                }

            if subdomain:
                grouped[key]["unique_subdomains"].add(subdomain)
            grouped[key]["total_bytes"] += qname_len
            grouped[key]["query_count"] += 1
            if rec.get("entropy", 0.0) > self.thresholds.entropy_threshold:
                grouped[key]["high_entropy_count"] += 1

        alerts: List[AlertDetail] = []
        card_thresh = self.thresholds.exfil_cardinality_threshold
        byte_thresh = self.thresholds.exfil_bytes_threshold

        for (src_ip, base_domain), stats in grouped.items():
            unique_subs_count = len(stats["unique_subdomains"])
            total_bytes = stats["total_bytes"]
            high_entropy_count = stats["high_entropy_count"]

            # Exfiltration triggered if EITHER unique subdomains OR total byte volume exceeds threshold
            is_cardinality_exfil = unique_subs_count >= card_thresh
            is_volumetric_exfil = total_bytes >= byte_thresh and unique_subs_count > 5

            if is_cardinality_exfil or is_volumetric_exfil:
                score = min(
                    1.0,
                    (unique_subs_count / card_thresh) * 0.5 + (total_bytes / byte_thresh) * 0.5,
                )
                severity = "CRITICAL" if score >= 0.8 else "HIGH"

                alerts.append(
                    AlertDetail(
                        detector_type="exfiltration",
                        rule_name="DNS_DATA_EXFILTRATION",
                        severity=severity,
                        description=(
                            f"DNS Data Exfiltration detected from {src_ip} to {base_domain}: "
                            f"{unique_subs_count} unique subdomains, {total_bytes} bytes payload"
                        ),
                        score=round(score, 2),
                        evidence={
                            "src_ip": src_ip,
                            "base_domain": base_domain,
                            "unique_subdomains_count": unique_subs_count,
                            "total_payload_bytes": total_bytes,
                            "total_query_count": stats["query_count"],
                            "high_entropy_queries": high_entropy_count,
                            "cardinality_threshold": card_thresh,
                            "bytes_threshold": byte_thresh,
                        },
                    )
                )

        return alerts
