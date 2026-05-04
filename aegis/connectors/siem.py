"""SIEM data source adapter.

Provides a unified interface for ingesting alerts from various SIEM/EDR
platforms and converting them to the canonical AegisThreat alert format.

Supported sources (Phase 1): Splunk, Elastic/ELK, SentinelOne, Suricata, Zeek.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Optional

from aegis.core.alert_dedup import AlertNormaliser, AlertDeduplicator

logger = logging.getLogger(__name__)


class SIEMAdapter(ABC):
    """Abstract SIEM adapter for pulling alerts from a security platform.

    Each adapter handles:
    1. Authentication and connection to the SIEM
    2. Polling or subscribing to alerts
    3. Converting platform-specific format to canonical AegisThreat format
    """

    def __init__(self, source_name: str) -> None:
        self._source = source_name
        self._normaliser = AlertNormaliser()

    @abstractmethod
    def fetch_alerts(self, since: Optional[datetime] = None) -> list[dict[str, Any]]:
        """Fetch alerts from the SIEM since the given timestamp.

        Returns alerts in canonical AegisThreat format.
        """
        ...

    @abstractmethod
    def is_connected(self) -> bool:
        ...

    def normalise(self, raw_alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Convert raw SIEM alerts to canonical format."""
        return self._normaliser.normalise_batch(raw_alerts, self._source)


class SplunkAdapter(SIEMAdapter):
    """Splunk Enterprise / Splunk Cloud adapter.

    Uses the Splunk REST API to search for recent notable events.
    """

    def __init__(self, host: str = "", port: int = 8089, token: str = "") -> None:
        super().__init__("splunk")
        self._host = host
        self._port = port
        self._token = token
        self._connected = False

    def is_connected(self) -> bool:
        return self._connected

    def fetch_alerts(self, since: Optional[datetime] = None) -> list[dict[str, Any]]:
        """Fetch alerts from Splunk via REST API.

        Phase 2+: Implement real Splunk API integration.
        For now, returns empty list with log message.
        """
        logger.warning("SplunkAdapter.fetch_alerts: not yet implemented (Phase 2+)")
        return []


class ElasticAdapter(SIEMAdapter):
    """Elasticsearch / ELK Stack adapter.

    Uses the Elasticsearch REST API to query for recent security alerts.
    """

    def __init__(self, host: str = "", api_key: str = "") -> None:
        super().__init__("elastic")
        self._host = host
        self._api_key = api_key
        self._connected = False

    def is_connected(self) -> bool:
        return self._connected

    def fetch_alerts(self, since: Optional[datetime] = None) -> list[dict[str, Any]]:
        logger.warning("ElasticAdapter.fetch_alerts: not yet implemented (Phase 2+)")
        return []


class SentinelOneAdapter(SIEMAdapter):
    """SentinelOne EDR adapter."""

    def __init__(self, api_token: str = "", url: str = "") -> None:
        super().__init__("sentinel_one")
        self._token = api_token
        self._url = url
        self._connected = False

    def is_connected(self) -> bool:
        return self._connected

    def fetch_alerts(self, since: Optional[datetime] = None) -> list[dict[str, Any]]:
        logger.warning("SentinelOneAdapter.fetch_alerts: not yet implemented (Phase 2+)")
        return []


class SuricataAdapter(SIEMAdapter):
    """Suricata IDS/IPS adapter — reads from eve.json log file."""

    def __init__(self, eve_json_path: str = "/var/log/suricata/eve.json") -> None:
        super().__init__("suricata")
        self._eve_path = eve_json_path
        self._last_position: int = 0

    def is_connected(self) -> bool:
        import os
        return os.path.exists(self._eve_path)

    def fetch_alerts(self, since: Optional[datetime] = None) -> list[dict[str, Any]]:
        """Read alerts from Suricata eve.json log file.

        This is the first adapter expected to work in Phase 1, since it
        only requires file access, not API integration.
        """
        import json
        import os

        if not self.is_connected():
            logger.warning("Suricata eve.json not found at %s", self._eve_path)
            return []

        raw_alerts: list[dict[str, Any]] = []
        try:
            file_size = os.path.getsize(self._eve_path)
            if file_size <= self._last_position:
                return []

            with open(self._eve_path, "r") as f:
                f.seek(self._last_position)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        if event.get("event_type") == "alert":
                            raw_alerts.append(event)
                    except json.JSONDecodeError:
                        continue
                self._last_position = f.tell()
        except Exception:
            logger.exception("Error reading Suricata eve.json")

        return self.normalise(raw_alerts)


class ZeekAdapter(SIEMAdapter):
    """Zeek (formerly Bro) network monitor adapter."""

    def __init__(self, log_dir: str = "/var/log/zeek") -> None:
        super().__init__("zeek")
        self._log_dir = log_dir

    def is_connected(self) -> bool:
        import os
        return os.path.isdir(self._log_dir)

    def fetch_alerts(self, since: Optional[datetime] = None) -> list[dict[str, Any]]:
        logger.warning("ZeekAdapter.fetch_alerts: not yet implemented (Phase 2+)")
        return []


def create_siem_adapter(source_type: str, **kwargs: Any) -> Optional[SIEMAdapter]:
    """Factory to create the appropriate SIEM adapter.

    Args:
        source_type: "splunk", "elastic", "sentinel_one", "suricata", "zeek".
        **kwargs: Passed to the adapter constructor.

    Returns:
        SIEMAdapter instance, or None if source_type is unrecognised.
    """
    adapters = {
        "splunk": SplunkAdapter,
        "elastic": ElasticAdapter,
        "sentinel_one": SentinelOneAdapter,
        "suricata": SuricataAdapter,
        "zeek": ZeekAdapter,
    }
    cls = adapters.get(source_type)
    if cls is None:
        logger.error("Unknown SIEM source type: %s", source_type)
        return None
    return cls(**kwargs)
