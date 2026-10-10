"""C2 Beaconing Detector using inter-arrival query time statistics and jitter analysis.

Groups queries by (src_ip, base_domain) and analyzes time deltas for low-jitter,
highly periodic heartbeat signatures characteristic of Command & Control channels.
"""

from typing import List, Dict, Any, Tuple
import numpy as np
from backend.app.config import get_config, ThresholdsConfig
from backend.app.models.schemas import AlertDetail
from backend.app.analytics.detectors import is_allowlisted_domain


class C2BeaconDetector:
    """Analyzes query timestamp sequences for C2 beacon periodicity."""

    def __init__(self, thresholds: ThresholdsConfig = None):
        self.thresholds = thresholds or get_config().thresholds

    def analyze_domain_group(
        self, src_ip: str, base_domain: str, timestamps: List[float]
    ) -> Tuple[float, float, float, bool]:
        """Analyze timestamp sequence for a specific (src_ip, base_domain) pair.

        Args:
            src_ip: Source IP address.
            base_domain: Root domain name.
            timestamps: Sorted list of query timestamps.

        Returns:
            Tuple of (mean_interval, std_dev, cv, is_beacon).
        """
        min_queries = self.thresholds.c2_min_queries
        jitter_threshold = self.thresholds.c2_jitter_threshold

        if len(timestamps) < min_queries:
            return 0.0, 0.0, 1.0, False

        sorted_ts = sorted(timestamps)
        deltas = np.diff(sorted_ts)

        # Ignore instantaneous duplicate bursts (< 0.01s)
        filtered_deltas = deltas[deltas >= 0.01]
        if len(filtered_deltas) < (min_queries - 1):
            return 0.0, 0.0, 1.0, False

        mean_interval = float(np.mean(filtered_deltas))
        std_dev = float(np.std(filtered_deltas))

        if mean_interval <= 0.0:
            return 0.0, 0.0, 1.0, False

        cv = float(std_dev / mean_interval)
        is_beacon = bool(cv < jitter_threshold and mean_interval >= 1.0)

        return round(mean_interval, 2), round(std_dev, 2), round(cv, 4), is_beacon

    def detect_beacons(self, records: List[Dict[str, Any]]) -> List[AlertDetail]:
        """Group records by (src_ip, base_domain) and detect periodic beaconing patterns.

        Args:
            records: List of enriched DNS query dictionaries.

        Returns:
            List of C2 Beaconing AlertDetail objects.
        """
        grouped: Dict[Tuple[str, str], List[float]] = {}
        for rec in records:
            src_ip = rec.get("src_ip", "0.0.0.0")
            base_domain = rec.get("base_domain", "")
            ts = rec.get("timestamp", 0.0)
            if rec.get("is_allowlisted") or is_allowlisted_domain(base_domain) or is_allowlisted_domain(rec.get("qname", "")):
                continue
            if base_domain and ts > 0.0:
                key = (src_ip, base_domain)
                grouped.setdefault(key, []).append(ts)

        alerts: List[AlertDetail] = []
        jitter_thresh = self.thresholds.c2_jitter_threshold

        for (src_ip, base_domain), timestamps in grouped.items():
            mean_int, std_dev, cv, is_beacon = self.analyze_domain_group(src_ip, base_domain, timestamps)

            if is_beacon:
                score = round(max(0.0, min(1.0, 1.0 - (cv / (jitter_thresh * 2.0)))), 2)
                alerts.append(
                    AlertDetail(
                        detector_type="c2_beacon",
                        rule_name="C2_PERIODIC_BEACONING",
                        severity="CRITICAL" if cv < (jitter_thresh / 2) else "HIGH",
                        description=(
                            f"Periodic C2 beaconing detected from {src_ip} to {base_domain}: "
                            f"Mean interval {mean_int}s, jitter CV {cv:.4f} (threshold {jitter_thresh})"
                        ),
                        score=score,
                        evidence={
                            "src_ip": src_ip,
                            "base_domain": base_domain,
                            "query_count": len(timestamps),
                            "mean_interval_sec": mean_int,
                            "std_dev_sec": std_dev,
                            "coefficient_of_variation": cv,
                            "threshold": jitter_thresh,
                        },
                    )
                )

        return alerts
