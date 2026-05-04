"""Alert deduplication and normalisation utilities.

Solves: same event reported by multiple sensors (SIEM + EDR + NGFW) should
be collapsed into a single canonical alert before entering the pipeline.

Strategy: entity-hash-based dedup within configurable time windows.
"""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


class AlertDeduplicator:
    """Deduplicate alerts based on entity hash within a sliding window.

    Two alerts are considered duplicates if they share the same
    (source_ip, destination_ip, action, time_bucket) tuple.
    """

    def __init__(self, window_seconds: int = 300, hash_fields: Optional[list[str]] = None) -> None:
        """
        Args:
            window_seconds: Dedup window in seconds (default 5 min).
            hash_fields: Fields to use for dedup hash.
                         Default: source_ip, destination_ip, action, rule_name.
        """
        self._window = timedelta(seconds=window_seconds)
        self._hash_fields = hash_fields or ["source_ip", "destination_ip", "action", "rule_name"]
        self._seen: dict[str, datetime] = {}  # hash → first_seen_at

    def _compute_hash(self, alert: dict[str, Any]) -> str:
        """Compute a stable hash from the specified fields."""
        raw = "|".join(str(alert.get(f, "")) for f in self._hash_fields)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def is_duplicate(self, alert: dict[str, Any], now: Optional[datetime] = None) -> bool:
        """Check if this alert is a duplicate of a recently-seen alert.

        Returns True if duplicate, False if new.
        Side effect: records this alert's hash if new.
        """
        now = now or datetime.now(timezone.utc)
        key = self._compute_hash(alert)

        # Prune expired entries first
        self._prune(now)

        if key in self._seen:
            logger.debug("Duplicate alert suppressed (hash=%s)", key)
            return True

        self._seen[key] = now
        return False

    def _prune(self, now: datetime) -> None:
        """Remove entries older than the window."""
        cutoff = now - self._window
        expired = [k for k, t in self._seen.items() if t < cutoff]
        for k in expired:
            del self._seen[k]

    def filter_alerts(self, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Filter a batch of alerts, returning only non-duplicates.

        Preserves input order.
        """
        now = datetime.now(timezone.utc)
        result: list[dict[str, Any]] = []
        for alert in alerts:
            if not self.is_duplicate(alert, now):
                result.append(alert)
        if len(result) < len(alerts):
            logger.info("Dedup: %d → %d alerts (%d suppressed)", len(alerts), len(result), len(alerts) - len(result))
        return result

    def reset(self) -> None:
        """Clear all seen hashes."""
        self._seen.clear()


class SeverityFilter:
    """Pre-filter alerts by severity to reduce noise before clustering.

    Only alerts at or above the configured severity threshold proceed.
    """

    SEVERITY_ORDER: dict[str, int] = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }

    def __init__(self, min_severity: str = "low") -> None:
        self._threshold = self.SEVERITY_ORDER.get(min_severity, 2)

    def should_process(self, alert: dict[str, Any]) -> bool:
        sev = alert.get("severity", "low").lower()
        return self.SEVERITY_ORDER.get(sev, 0) >= self._threshold

    def filter_alerts(self, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [a for a in alerts if self.should_process(a)]


class TwoStageClusterer:
    """Two-stage clustering: rule-based pre-filter → DBSCAN (Phase 2).

    Stage 1: Filter alerts by severity and deduplicate.
    Stage 2 (future): Apply DBSCAN on the remaining alerts.
    """

    def __init__(
        self,
        min_severity: str = "low",
        dedup_window_seconds: int = 300,
    ) -> None:
        self._severity_filter = SeverityFilter(min_severity)
        self._deduplicator = AlertDeduplicator(window_seconds=dedup_window_seconds)

    def prefilter(self, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Stage 1: severity filter → dedup → return candidates for clustering."""
        candidates = self._severity_filter.filter_alerts(alerts)
        if not candidates:
            return []
        return self._deduplicator.filter_alerts(candidates)


# ──────────────────────────────────────────────
# Schema Registry (stub for data normalisation)
# ──────────────────────────────────────────────


class AlertNormaliser:
    """Normalize heterogeneous alert formats into the standard AegisThreat schema.

    Maps SIEM-specific field names (e.g. Splunk "src_ip", SentinelOne "sourceIp")
    to the canonical field names used by DetectionAgent.
    """

    # Mapping: source_system → {canonical_field: [source_field_names]}
    FIELD_MAPS: dict[str, dict[str, list[str]]] = {
        "splunk": {
            "timestamp": ["_time", "timestamp", "event_time"],
            "source_ip": ["src_ip", "source_ip", "src", "client_ip"],
            "destination_ip": ["dest_ip", "destination_ip", "dst", "server_ip"],
            "hostname": ["host", "hostname", "computer_name", "dvc"],
            "username": ["user", "username", "src_user", "account_name"],
            "action": ["action", "event_name", "signature", "rule_description"],
            "severity": ["severity", "severity_id", "priority"],
            "rule_name": ["rule_name", "rule", "detection_name", "alert_name"],
        },
        "sentinel_one": {
            "timestamp": ["detectedAt", "timestamp", "createdAt"],
            "source_ip": ["sourceIp", "srcIp", "remoteIp"],
            "destination_ip": ["targetIp", "dstIp", "localIp"],
            "hostname": ["computerName", "hostname", "endpointName"],
            "username": ["user", "username", "lastLoggedInUser"],
            "action": ["threatName", "ruleName", "detectionType"],
            "severity": ["severity", "confidenceLevel", "threatLevel"],
            "rule_name": ["ruleName", "threatName", "engineName"],
        },
        "suricata": {
            "timestamp": ["timestamp", "flow.start"],
            "source_ip": ["src_ip", "flow.src_ip"],
            "destination_ip": ["dest_ip", "flow.dest_ip"],
            "hostname": ["host", "hostname"],
            "action": ["alert.signature", "alert.action", "action"],
            "severity": ["alert.severity", "flow.alerted"],
            "rule_name": ["alert.signature_id", "alert.signature"],
        },
    }

    @classmethod
    def normalise(cls, alert: dict[str, Any], source: str = "generic") -> dict[str, Any]:
        """Normalize a raw alert to canonical field names.

        Args:
            alert: Raw alert dict with source-specific field names.
            source: Source system identifier (splunk, sentinel_one, suricata, etc.)

        Returns:
            Dict with canonical field names (timestamp, source_ip, destination_ip,
            hostname, username, action, severity, rule_name).
        """
        field_map = cls.FIELD_MAPS.get(source, {})
        normalized: dict[str, Any] = {}

        for canonical, source_names in field_map.items():
            for name in source_names:
                if name in alert:
                    normalized[canonical] = alert[name]
                    break

        # Copy any unmapped fields as metadata
        normalized["_raw"] = {k: v for k, v in alert.items() if k not in normalized}
        normalized["_source"] = source

        return normalized

    @classmethod
    def normalise_batch(cls, alerts: list[dict[str, Any]], source: str = "generic") -> list[dict[str, Any]]:
        return [cls.normalise(a, source) for a in alerts]
