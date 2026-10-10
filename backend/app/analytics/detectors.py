"""Rule-based anomaly detector using thresholds from config.yaml.

Evaluates DNS queries against customizable rules including entropy,
length, character ratios, and high-risk query types.
"""

from typing import List, Dict, Any
from backend.app.config import get_config, ThresholdsConfig
from backend.app.models.schemas import AlertDetail


def is_allowlisted_domain(domain: str) -> bool:
    """Check if a domain or base_domain matches mDNS/DNS-SD reserved allowlist patterns (RFC 6762).

    Skip rule-based and ML scoring entirely if base_domain ends with '.local'
    or starts with '_tcp.' or '_udp.' (case-insensitive).
    """
    if not domain:
        return False
    d = str(domain).lower().strip().rstrip(".")
    return d.endswith(".local") or d.startswith("_tcp.") or d.startswith("_udp.") or d == "local"


class RuleBasedDetector:
    """Evaluates DNS query records against threshold-driven detection rules."""

    def __init__(self, thresholds: ThresholdsConfig = None):
        self.thresholds = thresholds or get_config().thresholds

    def evaluate_record(self, record: Dict[str, Any]) -> List[AlertDetail]:
        """Evaluate a single enriched DNS query record against rules.

        Args:
            record: Enriched DNS query dictionary.

        Returns:
            List of triggered AlertDetail objects.
        """
        alerts: List[AlertDetail] = []
        t = self.thresholds

        base_domain = record.get("base_domain", "")
        qname = record.get("qname", "")
        if record.get("is_allowlisted") or is_allowlisted_domain(base_domain) or is_allowlisted_domain(qname):
            return []

        subdomain = record.get("subdomain", "")
        sub_len = record.get("subdomain_len", 0)
        entropy = record.get("entropy", 0.0)
        digit_ratio = record.get("digit_ratio", 0.0)
        hex_ratio = record.get("hex_ratio", 0.0)
        qtype = record.get("qtype", "A")

        # 1. High Shannon Entropy Rule
        if sub_len > 8 and entropy > t.entropy_threshold:
            alerts.append(
                AlertDetail(
                    detector_type="rule",
                    rule_name="HIGH_SUBDOMAIN_ENTROPY",
                    severity="HIGH" if entropy > (t.entropy_threshold + 0.5) else "MEDIUM",
                    description=f"Subdomain entropy {entropy:.2f} exceeds threshold {t.entropy_threshold}",
                    score=min(1.0, (entropy - t.entropy_threshold) / 2.0 + 0.5),
                    evidence={"subdomain": subdomain, "entropy": entropy, "threshold": t.entropy_threshold},
                )
            )

        # 2. Long Subdomain Length Rule
        if sub_len > t.subdomain_length_threshold:
            alerts.append(
                AlertDetail(
                    detector_type="rule",
                    rule_name="LONG_SUBDOMAIN_LENGTH",
                    severity="HIGH" if sub_len > (t.subdomain_length_threshold + 20) else "MEDIUM",
                    description=f"Subdomain length {sub_len} exceeds threshold {t.subdomain_length_threshold}",
                    score=min(1.0, sub_len / 100.0),
                    evidence={"subdomain": subdomain, "length": sub_len, "threshold": t.subdomain_length_threshold},
                )
            )

        # 3. High Digit Ratio Rule
        if sub_len > 10 and digit_ratio > t.digit_ratio_threshold:
            alerts.append(
                AlertDetail(
                    detector_type="rule",
                    rule_name="HIGH_DIGIT_RATIO",
                    severity="MEDIUM",
                    description=f"Digit ratio {digit_ratio:.2f} exceeds threshold {t.digit_ratio_threshold}",
                    score=min(1.0, digit_ratio),
                    evidence={"subdomain": subdomain, "digit_ratio": digit_ratio},
                )
            )

        # 4. High Hexadecimal Ratio Rule
        if sub_len > 10 and hex_ratio > t.hex_ratio_threshold:
            alerts.append(
                AlertDetail(
                    detector_type="rule",
                    rule_name="HIGH_HEX_RATIO",
                    severity="MEDIUM",
                    description=f"Hex character ratio {hex_ratio:.2f} exceeds threshold {t.hex_ratio_threshold}",
                    score=min(1.0, hex_ratio),
                    evidence={"subdomain": subdomain, "hex_ratio": hex_ratio},
                )
            )

        # 5. High-Risk Query Type with Payload Rule (TXT, CNAME, NULL)
        if qtype in {"TXT", "CNAME", "NULL"} and sub_len > 15:
            alerts.append(
                AlertDetail(
                    detector_type="rule",
                    rule_name="HIGH_RISK_QTYPE_PAYLOAD",
                    severity="HIGH",
                    description=f"Query type {qtype} with encoded subdomain payload of length {sub_len}",
                    score=0.75,
                    evidence={"qtype": qtype, "subdomain": subdomain, "length": sub_len},
                )
            )

        return alerts

    def evaluate_batch(self, records: List[Dict[str, Any]]) -> List[AlertDetail]:
        """Evaluate a batch of records against rules.

        Args:
            records: List of enriched DNS query dictionaries.

        Returns:
            Flattens list of alerts.
        """
        all_alerts: List[AlertDetail] = []
        for rec in records:
            all_alerts.extend(self.evaluate_record(rec))
        return all_alerts
