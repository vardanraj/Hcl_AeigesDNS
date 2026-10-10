"""Adaptive time window bucketer for AegisDNS timeline charts.

Dynamically computes bucket sizes (5s, 10s, 1m, 5m) based on capture duration
so single short captures and long packet streams always display multiple timeline points.
"""

from typing import List, Dict, Any
import time
from backend.app.models.schemas import TimelineDataPoint


def build_adaptive_timeline(records: List[Dict[str, Any]], config) -> List[TimelineDataPoint]:
    """Build adaptive timeline data points for DNS queries and anomalies.

    Args:
        records: List of enriched DNS query record dicts with float timestamps.
        config: AppConfig instance containing detection thresholds.

    Returns:
        Sorted list of TimelineDataPoint schema objects.
    """
    if not records:
        return []

    timestamps = [r.get("timestamp", 0.0) for r in records if r.get("timestamp", 0.0) > 0.0]
    if not timestamps:
        return []

    t_min = min(timestamps)
    t_max = max(timestamps)
    duration = t_max - t_min

    # Determine adaptive bucket interval in seconds
    if duration <= 10.0:
        bucket_size = 2.0
        time_format = "%H:%M:%S"
    elif duration <= 60.0:
        bucket_size = 5.0
        time_format = "%H:%M:%S"
    elif duration <= 600.0:
        bucket_size = 30.0
        time_format = "%H:%M:%S"
    elif duration <= 3600.0:
        bucket_size = 60.0
        time_format = "%H:%M"
    else:
        bucket_size = 300.0
        time_format = "%H:%M"

    buckets: Dict[str, Dict[str, Any]] = {}

    for r in records:
        ts = r.get("timestamp", t_min)
        # Calculate bucket index relative to t_min
        bucket_idx = int((ts - t_min) // bucket_size)
        bucket_ts = t_min + (bucket_idx * bucket_size)
        label = time.strftime(time_format, time.localtime(bucket_ts))

        if label not in buckets:
            buckets[label] = {"bucket_ts": bucket_ts, "queries": 0, "anomalies": 0}

        buckets[label]["queries"] += 1

        # Check anomaly triggers
        is_anom = (
            r.get("entropy", 0.0) > config.thresholds.entropy_threshold
            or r.get("subdomain_len", 0) > config.thresholds.subdomain_length_threshold
            or r.get("qtype") in ["TXT", "NULL"]
        )
        if is_anom:
            buckets[label]["anomalies"] += 1

    # Sort buckets chronologically
    sorted_buckets = sorted(buckets.values(), key=lambda b: b["bucket_ts"])

    return [
        TimelineDataPoint(
            timestamp=b["label"] if "label" in b else time.strftime(time_format, time.localtime(b["bucket_ts"])),
            total_queries=b["queries"],
            anomalous_queries=b["anomalies"],
        )
        for b in sorted_buckets
    ]
