"""Detection Agent — fuses heterogeneous alerts into AttackFragments.

Phase 1 (MVP): Rule-based alert aggregation with template summaries,
               alert deduplication, dual-window (fast/slow), and schema normalisation.
Phase 2+: DBSCAN clustering, FastText/SecureBERT vectorization, Llama-3-8B summaries.

Input:  SIEM/EDR/NGFW alerts (via Kafka or direct push)
Output: AttackFragment published to threat.fragment
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import numpy as np

from aegis.agents.base import BaseAgent
from aegis.core.alert_dedup import AlertDeduplicator, AlertNormaliser, TwoStageClusterer
from aegis.core.models import (
    AgentRole,
    AttackFragment,
    ConfidenceLevel,
    Entity,
    TTPMapping,
)

logger = logging.getLogger(__name__)


ALERT_TO_TTP: dict[str, tuple[list[str], list[str]]] = {
    "brute_force": (["T1110"], ["brute force", "password spray", "credential guessing", "failed login"]),
    "credential_dump": (["T1003"], ["mimikatz", "lsass dump", "credential dumping", "procdump", "sekurlsa"]),
    "credential_theft": (["T1552", "T1555"], ["credential theft", "password store", "keychain", "vault"]),
    "phishing": (["T1566"], ["phishing", "spear-phishing", "malicious email", "spoofed sender"]),
    "drive_by": (["T1189"], ["drive-by", "malvertising", "waterhole", "compromised website"]),
    "exploitation": (["T1190", "T1210"], ["exploit", "cve", "remote code execution", "rce", "shell injection"]),
    "external_remote": (["T1133"], ["external remote", "vpn anomaly", "rdp brute", "exposed port"]),
    "suspicious_execution": (["T1059"], ["powershell", "cmd.exe", "wscript", "cscript", "bash -c", "python -c"]),
    "macro_execution": (["T1204"], ["macro", "vba", "office document", "enable content", "malicious doc"]),
    "exploit_client": (["T1203"], ["browser exploit", "flash", "pdf exploit", "office exploit"]),
    "persistence": (["T1547", "T1053"], ["scheduled task", "registry run", "startup folder", "launch agent", "cron"]),
    "server_compromise": (["T1505"], ["web shell", "sql injection", "server-side", "backdoor"]),
    "privilege_escalation": (["T1068"], ["sudo", "admin access", "uac bypass", "token manipulation", "suid"]),
    "defense_evasion": (["T1562", "T1070"], ["disable av", "log clear", "defender stopped", "firewall disabled", "amsi bypass"]),
    "obfuscation": (["T1027"], ["obfuscated", "base64 encoded", "encoded command", "packed executable"]),
    "reconnaissance": (["T1595", "T1046"], ["port scan", "vuln scan", "network sweep", "service enumeration"]),
    "discovery": (["T1083", "T1016"], ["file enumeration", "system info", "whoami", "net view", "dir /s", "ls -laR"]),
    "lateral_movement": (["T1021", "T1570"], ["psexec", "wmic", "smb", "rdp lateral", "ssh lateral", "winrm"]),
    "c2_communication": (["T1071", "T1573"], ["beacon", "command and control", "callback", "post-exploitation", "c2 channel"]),
    "dns_tunneling": (["T1572"], ["dns tunnel", "dns beacon", "txt record", "long dns query"]),
    "data_exfil": (["T1048", "T1567"], ["exfiltration", "large upload", "data staging", "archive then transfer"]),
    "data_destruction": (["T1485", "T1486"], ["ransomware", "encryption", "shadow copy delete", "wiped", "destruction"]),
    "suspicious_update": (["T1195"], ["supply chain", "compromised update", "backdoored software"]),
    "suspicious_login": (["T1078"], ["impossible travel", "off-hours login", "anomalous geo", "new device"]),
    "anomalous_process": (["T1059", "T1547"], ["unusual parent process", "process hollowing", "dll sideload"]),
    "malware_download": (["T1105", "T1204"], ["suspicious download", "trojan", "dropper", "staged payload"]),
    "reverse_shell": (["T1059", "T1071"], ["reverse shell", "connect-back", "bind shell", "netcat listener"]),
}


class DetectionAgent(BaseAgent):
    """Alert Fusion Agent — clusters raw alerts into AttackFragments.

    Improvements over original design:
    - Dual-window: 5-minute fast-track for critical alerts + 30-minute full window
    - Alert deduplication: entity-hash-based dedup within 5-minute window
    - Schema normalisation: maps Splunk/SentinelOne/Suricata fields to canonical names
    - Severity pre-filtering: only medium+ alerts enter the pipeline by default
    """

    @property
    def agent_role(self) -> AgentRole:
        return AgentRole.DETECTION

    def __init__(
        self,
        agent_id: str = "",
        window_minutes: int = 30,
        fast_window_minutes: int = 5,
        min_alerts_per_fragment: int = 3,
        min_severity: str = "low",
        dedup_window_seconds: int = 300,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_id=agent_id, **kwargs)
        self._fast_window = timedelta(minutes=fast_window_minutes)
        self._full_window = timedelta(minutes=window_minutes)
        self._min_alerts = min_alerts_per_fragment
        self._alert_buffer: list[dict[str, Any]] = []
        self._fast_buffer: list[dict[str, Any]] = []
        self._deduplicator = AlertDeduplicator(window_seconds=dedup_window_seconds)
        self._clusterer = TwoStageClusterer(min_severity=min_severity, dedup_window_seconds=dedup_window_seconds)

    def on_fragment(self, fragment: AttackFragment, correlation_id: Optional[str]) -> None:
        logger.warning("DetectionAgent received a fragment unexpectedly — ignoring")

    def ingest_alert(
        self,
        alert: dict[str, Any],
        source: str = "generic",
    ) -> Optional[AttackFragment]:
        if source != "generic":
            alert = AlertNormaliser.normalise(alert, source)
        if self._deduplicator.is_duplicate(alert):
            return None
        severity = alert.get("severity", "low")
        is_critical = severity in ("critical", "high")
        if is_critical:
            self._fast_buffer.append(alert)
        self._alert_buffer.append(alert)
        self._prune_expired(self._fast_buffer, self._fast_window)
        self._prune_expired(self._alert_buffer, self._full_window)
        if len(self._fast_buffer) >= max(1, self._min_alerts // 3):
            fragment = self._build_fragment(self._fast_buffer, is_fast_track=True)
            if fragment and fragment.confidence >= 0.3:
                self._fast_buffer.clear()
                self._alert_buffer = [a for a in self._alert_buffer if a not in self._fast_buffer]
                logger.info("FAST-TRACK fragment: %s", fragment.to_summary_string())
                return fragment
        if len(self._alert_buffer) >= self._min_alerts:
            fragment = self._build_fragment(self._alert_buffer, is_fast_track=False)
            if fragment is None:
                return None
            if fragment.confidence < 0.3:
                logger.debug("Fragment %s confidence too low (%.2f), discarding", fragment.fragment_id, fragment.confidence)
                return None
            self._alert_buffer.clear()
            self._fast_buffer.clear()
            logger.info("Generated fragment: %s", fragment.to_summary_string())
            return fragment
        return None

    def ingest_and_publish(self, alert: dict[str, Any], source: str = "generic") -> Optional[AttackFragment]:
        fragment = self.ingest_alert(alert, source)
        if fragment:
            self.publish_fragment(fragment)
        return fragment

    def ingest_batch(
        self,
        alerts: list[dict[str, Any]],
        source: str = "generic",
    ) -> list[AttackFragment]:
        candidates = self._clusterer.prefilter(alerts)
        if source != "generic":
            candidates = AlertNormaliser.normalise_batch(candidates, source)
        fragments: list[AttackFragment] = []
        for alert in candidates:
            frag = self.ingest_and_publish(alert, source="generic")
            if frag:
                fragments.append(frag)
        logger.info("Batch: %d alerts -> %d fragments", len(alerts), len(fragments))
        return fragments

    def _prune_expired(self, buffer: list[dict[str, Any]], window: timedelta) -> None:
        cutoff = datetime.now(timezone.utc) - window
        buffer[:] = [
            a for a in buffer
            if self._parse_timestamp(a.get("timestamp")) > cutoff
        ]

    @staticmethod
    def _parse_timestamp(ts: Any) -> datetime:
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return datetime.now(timezone.utc)

    def _extract_entities(self, alerts: list[dict[str, Any]]) -> list[Entity]:
        seen: set[tuple[str, str]] = set()
        entities: list[Entity] = []
        for alert in alerts:
            for field, etype in [
                ("source_ip", "ip"), ("destination_ip", "ip"),
                ("hostname", "host"), ("username", "user"),
                ("file_hash", "hash"), ("domain", "domain"),
                ("process_name", "process"),
            ]:
                val = alert.get(field)
                if val and (etype, str(val)) not in seen:
                    seen.add((etype, str(val)))
                    entities.append(Entity(entity_type=etype, value=str(val)))
        return entities

    def _map_ttps(self, alerts: list[dict[str, Any]]) -> list[TTPMapping]:
        ttp_scores: dict[str, float] = {}
        ttp_names: dict[str, str] = {}
        ttp_evidence: dict[str, list[str]] = {}
        for alert in alerts:
            rule = alert.get("rule_name", "").lower()
            action_text = alert.get("action", "").lower()
            for pattern, (ttps, keywords) in ALERT_TO_TTP.items():
                matched = (
                    pattern in rule
                    or any(kw.lower() in rule for kw in keywords)
                    or any(kw.lower() in action_text for kw in keywords)
                )
                if not matched:
                    continue
                for ttp in ttps:
                    ttp_scores[ttp] = ttp_scores.get(ttp, 0) + 1
                    ttp_names[ttp] = ttp_names.get(ttp, pattern)
                    evidence_line = (
                        f"[{alert.get('rule_name', '?')}] {alert.get('action', '')[:100]}"
                    )
                    if alert.get("hostname"):
                        evidence_line += f" (host={alert['hostname']})"
                    if alert.get("username"):
                        evidence_line += f" (user={alert['username']})"
                    ttp_evidence.setdefault(ttp, []).append(evidence_line)
        max_count = max(ttp_scores.values()) if ttp_scores else 1
        return [
            TTPMapping(
                technique_id=tid,
                technique_name=ttp_names.get(tid, ""),
                confidence=min(1.0, round(count / max_count, 4)),
                evidence=" | ".join(ttp_evidence.get(tid, [])[:3]),
            )
            for tid, count in sorted(ttp_scores.items(), key=lambda x: -x[1])
        ]

    def _compute_confidence(self, alerts: list[dict[str, Any]], ttps: list[TTPMapping]) -> float:
        if not ttps:
            return 0.0
        ttp_factor = min(1.0, len(ttps) / 5.0)
        severity_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.1}
        sev_scores = [severity_map.get(a.get("severity", "low"), 0.1) for a in alerts]
        severity_avg = np.mean(sev_scores) if sev_scores else 0.0
        ttp_avg = np.mean([t.confidence for t in ttps]) if ttps else 0.0
        entities = self._extract_entities(alerts)
        entity_factor = min(1.0, len(entities) / 6.0)
        timestamps = [self._parse_timestamp(a.get("timestamp")) for a in alerts]
        if len(timestamps) >= 2:
            span_minutes = max(1, (max(timestamps) - min(timestamps)).total_seconds() / 60)
            density = len(alerts) / span_minutes
            density_factor = min(1.0, density / 10.0)
        else:
            density_factor = 0.3
        return round(float(
            0.25 * ttp_factor + 0.20 * severity_avg + 0.20 * ttp_avg
            + 0.15 * entity_factor + 0.20 * density_factor
        ), 4)

    def _generate_summary(self, alerts: list[dict[str, Any]], ttps: list[TTPMapping]) -> str:
        unique_ips: set[str] = set()
        unique_hosts: set[str] = set()
        actions: list[str] = []
        for a in alerts:
            if a.get("source_ip"):
                unique_ips.add(str(a["source_ip"]))
            if a.get("destination_ip"):
                unique_ips.add(str(a["destination_ip"]))
            if a.get("hostname"):
                unique_hosts.add(str(a["hostname"]))
            if a.get("action"):
                actions.append(str(a["action"]))
        parts: list[str] = []
        if unique_ips:
            parts.append(f"IP: {', '.join(sorted(unique_ips)[:5])}")
        if unique_hosts:
            parts.append(f"Hosts: {', '.join(sorted(unique_hosts)[:5])}")
        if ttps:
            ttp_str = ", ".join(t.technique_id for t in ttps[:5])
            parts.append(f"TTPs: {ttp_str}")
        if actions:
            distinct = list(dict.fromkeys(actions))[:5]
            parts.append(f"Actions: {' -> '.join(distinct)}")
        return ". ".join(parts) + "."

    def _build_fragment(
        self,
        alerts: list[dict[str, Any]],
        is_fast_track: bool = False,
    ) -> Optional[AttackFragment]:
        if not alerts:
            return None
        entities = self._extract_entities(alerts)
        ttps = self._map_ttps(alerts)
        confidence = self._compute_confidence(alerts, ttps)
        if is_fast_track:
            confidence = min(1.0, confidence + 0.1)
        summary = self._generate_summary(alerts, ttps)
        timestamps = [self._parse_timestamp(a.get("timestamp")) for a in alerts]
        ts_min = min(timestamps)
        ts_max = max(timestamps)
        return AttackFragment(
            entities=entities,
            summary=summary,
            suspected_ttps=ttps,
            confidence=confidence,
            confidence_level=ConfidenceLevel.LOW,
            timestamp_span=(ts_min, ts_max),
            raw_alert_count=len(alerts),
        )
