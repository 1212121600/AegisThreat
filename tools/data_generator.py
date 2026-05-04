#!/usr/bin/env python3
"""Synthetic Attack Data Generator for AegisThreat.

Generates realistic-but-fake alert sequences that simulate APT attack chains.
Critical for Phase 0: solves the cold-start problem by providing training and
demonstration data without requiring real enterprise SIEM data.

Usage:
    python tools/data_generator.py --scenario phishing-to-exfil --count 50
    python tools/data_generator.py --scenario brute-force-lateral --output alerts.json
"""

from __future__ import annotations

import json
import logging
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# Attack Scenario Templates
# ──────────────────────────────────────────────

# Each scenario defines a sequence of alerts that together form an APT chain.
# Timestamps are relative offsets from the scenario start time.

ScenarioStep = dict[str, Any]
Scenario = dict[str, Any]

SCENARIOS: dict[str, Scenario] = {
    # ── Scenario 1: Spear-phishing → C2 → Credential Dump → Lateral Movement → Exfil ──
    "phishing-to-exfil": {
        "name": "Spear-Phishing to Data Exfiltration",
        "description": "APT29-style attack: phishing email with malicious attachment, "
                       "macro execution, C2 beacon, credential dumping, lateral movement, "
                       "and data exfiltration.",
        "ttp_sequence": ["T1566", "T1204", "T1059", "T1071", "T1003", "T1021", "T1083", "T1048"],
        "entities": {
            "attacker_ip": ["185.220.101.34", "185.220.101.35"],  # C2 IPs
            "c2_domain": ["update-service[.]net", "cdn-cache[.]com"],
            "target_hosts": ["ws-finance-07.corp.local", "ws-finance-12.corp.local",
                            "dc-file-01.corp.local", "db-sql-03.corp.local"],
            "target_users": ["jwilson", "svc_backup"],
            "malware_hashes": ["a1b2c3d4e5f6", "d4e5f6a1b2c3"],
        },
        "steps": [
            {
                "offset_minutes": 0,
                "alerts": [
                    {"rule_name": "phishing_email_detected", "action": "email with malicious attachment delivered to jwilson@corp.local", "severity": "high", "source_ip": "45.67.89.10"},
                ]
            },
            {
                "offset_minutes": 5,
                "alerts": [
                    {"rule_name": "macro_execution_detected", "action": "Word macro executed PowerShell download cradle", "severity": "critical", "hostname": "ws-finance-07.corp.local", "username": "jwilson"},
                ]
            },
            {
                "offset_minutes": 8,
                "alerts": [
                    {"rule_name": "suspicious_download", "action": "PowerShell downloaded payload from update-service[.]net", "severity": "high", "source_ip": "185.220.101.34", "hostname": "ws-finance-07.corp.local"},
                ]
            },
            {
                "offset_minutes": 10,
                "alerts": [
                    {"rule_name": "c2_communication", "action": "Beacon to 185.220.101.34:443 every 60s (HTTPS)", "severity": "critical", "hostname": "ws-finance-07.corp.local", "domain": "update-service[.]net"},
                ]
            },
            {
                "offset_minutes": 25,
                "alerts": [
                    {"rule_name": "credential_dump", "action": "LSASS memory dump via procdump", "severity": "critical", "hostname": "ws-finance-07.corp.local", "file_hash": "a1b2c3d4e5f6"},
                ]
            },
            {
                "offset_minutes": 35,
                "alerts": [
                    {"rule_name": "privilege_escalation", "action": "Token manipulation to SYSTEM", "severity": "critical", "hostname": "ws-finance-07.corp.local"},
                ]
            },
            {
                "offset_minutes": 45,
                "alerts": [
                    {"rule_name": "lateral_movement", "action": "PsExec to dc-file-01.corp.local using svc_backup credentials", "severity": "critical", "source_ip": "ws-finance-07.corp.local", "destination_ip": "dc-file-01.corp.local", "username": "svc_backup"},
                ]
            },
            {
                "offset_minutes": 55,
                "alerts": [
                    {"rule_name": "reconnaissance", "action": "Directory enumeration on file server", "severity": "high", "hostname": "dc-file-01.corp.local"},
                ]
            },
            {
                "offset_minutes": 70,
                "alerts": [
                    {"rule_name": "data_exfil", "action": "Large outbound file transfer (2.3GB) to 185.220.101.35 via HTTPS", "severity": "critical", "source_ip": "dc-file-01.corp.local", "destination_ip": "185.220.101.35"},
                ]
            },
        ],
    },

    # ── Scenario 2: Brute Force → Valid Account → Lateral → Data Destruction ──
    "brute-force-lateral": {
        "name": "Brute Force to Lateral Movement & Destruction",
        "description": "External brute force on VPN, successful login, lateral movement "
                       "via RDP, credential dumping, and data destruction.",
        "ttp_sequence": ["T1110", "T1078", "T1021", "T1003", "T1485"],
        "entities": {
            "attacker_ip": ["91.234.55.12"],
            "target_hosts": ["vpn-gateway.corp.local", "ws-hr-03.corp.local",
                            "dc-corp-01.corp.local", "db-hr-02.corp.local"],
            "target_users": ["asmith", "domain_admin"],
            "malware_hashes": ["f7e8d9c0a1b2"],
        },
        "steps": [
            {
                "offset_minutes": 0,
                "alerts": [
                    {"rule_name": "brute_force", "action": "VPN brute force on account asmith (500+ attempts)", "severity": "high", "source_ip": "91.234.55.12", "destination_ip": "vpn-gateway.corp.local", "username": "asmith"},
                ]
            },
            {
                "offset_minutes": 12,
                "alerts": [
                    {"rule_name": "brute_force_success", "action": "Successful VPN login for asmith from 91.234.55.12", "severity": "critical", "source_ip": "91.234.55.12", "username": "asmith"},
                ]
            },
            {
                "offset_minutes": 15,
                "alerts": [
                    {"rule_name": "anomalous_login", "action": "Off-hours login from unusual geo-location", "severity": "high", "username": "asmith", "hostname": "ws-hr-03.corp.local"},
                ]
            },
            {
                "offset_minutes": 25,
                "alerts": [
                    {"rule_name": "privilege_escalation", "action": "Local privilege escalation via UAC bypass", "severity": "critical", "hostname": "ws-hr-03.corp.local"},
                ]
            },
            {
                "offset_minutes": 35,
                "alerts": [
                    {"rule_name": "credential_dump", "action": "Domain credential dumping via DCSync", "severity": "critical", "hostname": "ws-hr-03.corp.local", "username": "domain_admin"},
                ]
            },
            {
                "offset_minutes": 50,
                "alerts": [
                    {"rule_name": "lateral_movement", "action": "RDP to dc-corp-01.corp.local using domain_admin", "severity": "critical", "source_ip": "ws-hr-03.corp.local", "destination_ip": "dc-corp-01.corp.local"},
                ]
            },
            {
                "offset_minutes": 65,
                "alerts": [
                    {"rule_name": "defense_evasion", "action": "Windows Defender disabled via registry", "severity": "critical", "hostname": "dc-corp-01.corp.local"},
                ]
            },
            {
                "offset_minutes": 80,
                "alerts": [
                    {"rule_name": "data_destruction", "action": "Shadow copy deletion and file encryption", "severity": "critical", "hostname": "dc-corp-01.corp.local", "file_hash": "f7e8d9c0a1b2"},
                ]
            },
        ],
    },

    # ── Scenario 3: Web App Exploit → C2 → Data Exfil (short chain) ──
    "webapp-exploit": {
        "name": "Web Application Exploit to Data Exfiltration",
        "description": "Exploit of public-facing web app, reverse shell, "
                       "credential theft, and database dump.",
        "ttp_sequence": ["T1190", "T1059", "T1071", "T1003", "T1048"],
        "entities": {
            "attacker_ip": ["198.51.100.23", "203.0.113.45"],
            "target_hosts": ["web-app-01.corp.local", "db-mysql-01.corp.local"],
            "target_users": ["www-data"],
        },
        "steps": [
            {
                "offset_minutes": 0,
                "alerts": [
                    {"rule_name": "exploitation_attempt", "action": "SQL injection via vulnerable /api/search endpoint", "severity": "high", "source_ip": "198.51.100.23", "destination_ip": "web-app-01.corp.local"},
                ]
            },
            {
                "offset_minutes": 2,
                "alerts": [
                    {"rule_name": "exploitation_success", "action": "Remote code execution on web-app-01 via CVE-2025-XXXXX", "severity": "critical", "source_ip": "198.51.100.23", "hostname": "web-app-01.corp.local"},
                ]
            },
            {
                "offset_minutes": 5,
                "alerts": [
                    {"rule_name": "reverse_shell", "action": "Reverse shell from web-app-01 to 203.0.113.45:4444", "severity": "critical", "hostname": "web-app-01.corp.local", "destination_ip": "203.0.113.45"},
                ]
            },
            {
                "offset_minutes": 10,
                "alerts": [
                    {"rule_name": "linux_credential_access", "action": "Reading /etc/shadow and MySQL config files", "severity": "high", "hostname": "web-app-01.corp.local"},
                ]
            },
            {
                "offset_minutes": 20,
                "alerts": [
                    {"rule_name": "data_exfil", "action": "MySQL dump (12GB) exfiltrated to 203.0.113.45 via SCP", "severity": "critical", "hostname": "web-app-01.corp.local"},
                ]
            },
        ],
    },

    # ── Scenario 4: Supply Chain → C2 → Persistence (SolarWinds-style) ──
    "supply-chain": {
        "name": "Supply Chain Compromise with Long Dwell Time",
        "description": "Compromised software update, delayed C2 activation, "
                       "persistence via scheduled tasks, and long-term data collection.",
        "ttp_sequence": ["T1195", "T1071", "T1547", "T1083", "T1560", "T1048"],
        "entities": {
            "attacker_ip": ["10.0.0.1"],  # Often internal C2 after supply chain
            "c2_domain": ["telem-gw[.]internal", "stat-collector[.]com"],
            "target_hosts": ["ws-eng-14.corp.local", "ws-eng-22.corp.local", "build-server-01.corp.local"],
            "malware_hashes": ["deadbeefcafe"],
        },
        "steps": [
            {
                "offset_minutes": 0,
                "alerts": [
                    {"rule_name": "suspicious_update", "action": "Software update binary signed with unexpected certificate", "severity": "medium", "hostname": "build-server-01.corp.local"},
                ]
            },
            {
                "offset_minutes": 120,  # 2 hour dwell
                "alerts": [
                    {"rule_name": "c2_communication", "action": "DNS beacon to telem-gw.internal (every 15 min)", "severity": "high", "hostname": "build-server-01.corp.local", "domain": "telem-gw.internal"},
                ]
            },
            {
                "offset_minutes": 180,
                "alerts": [
                    {"rule_name": "persistence", "action": "Scheduled task 'WindowsUpdateCheck' created for SYSTEM persistence", "severity": "high", "hostname": "build-server-01.corp.local"},
                ]
            },
            {
                "offset_minutes": 240,
                "alerts": [
                    {"rule_name": "reconnaissance", "action": "Network scan from build-server-01 to engineering subnet", "severity": "medium", "hostname": "build-server-01.corp.local"},
                ]
            },
            {
                "offset_minutes": 360,
                "alerts": [
                    {"rule_name": "data_collection", "action": "Archive of source code repos (45GB compressed)", "severity": "high", "hostname": "build-server-01.corp.local"},
                ]
            },
            {
                "offset_minutes": 480,
                "alerts": [
                    {"rule_name": "data_exfil", "action": "Slow HTTPS exfiltration (rate-limited) to stat-collector.com", "severity": "high", "hostname": "build-server-01.corp.local", "domain": "stat-collector.com"},
                ]
            },
        ],
    },
}


class DataGenerator:
    """Generate synthetic alert sequences based on attack scenario templates.

    Each scenario produces a realistic timeline of alerts that the Detection
    Agent can cluster into AttackFragments.
    """

    def __init__(self, base_time: Optional[datetime] = None, seed: int = 42) -> None:
        self.base_time = base_time or datetime.now(timezone.utc) - timedelta(hours=2)
        random.seed(seed)
        self.rng = random.Random(seed)

    def generate_from_scenario(self, scenario_name: str) -> list[dict[str, Any]]:
        """Generate all alerts for a named scenario.

        Args:
            scenario_name: Key in SCENARIOS dict (e.g. "phishing-to-exfil")

        Returns:
            List of alert dicts with realistic timestamps.
        """
        scenario = SCENARIOS.get(scenario_name)
        if not scenario:
            raise ValueError(f"Unknown scenario: {scenario_name}. Available: {list(SCENARIOS.keys())}")

        entities = scenario["entities"]
        alerts: list[dict[str, Any]] = []

        for step in scenario["steps"]:
            offset = step["offset_minutes"]
            step_time = self.base_time + timedelta(minutes=offset)

            for alert_tmpl in step["alerts"]:
                alert = dict(alert_tmpl)
                alert["timestamp"] = step_time.isoformat()
                alert["alert_id"] = f"alert-{uuid.uuid4().hex[:12]}"

                # Fill in entity defaults from scenario
                if "source_ip" not in alert and "attacker_ip" in entities:
                    alert["source_ip"] = self.rng.choice(entities["attacker_ip"])
                if "hostname" not in alert and "target_hosts" in entities:
                    alert["hostname"] = self.rng.choice(entities["target_hosts"])
                if "username" not in alert and "target_users" in entities:
                    alert["username"] = self.rng.choice(entities["target_users"])
                if "file_hash" not in alert and "malware_hashes" in entities:
                    alert["file_hash"] = self.rng.choice(entities["malware_hashes"])
                if "destination_ip" not in alert:
                    # Infer from scenario steps
                    pass

                # Add jitter for realism (±30 seconds)
                jitter = self.rng.randint(-30, 30)
                alert_time = step_time + timedelta(seconds=jitter)
                alert["timestamp"] = alert_time.isoformat()

                alerts.append(alert)

        return sorted(alerts, key=lambda a: a["timestamp"])

    def generate_all_scenarios(self) -> dict[str, list[dict[str, Any]]]:
        """Generate alerts for all predefined scenarios."""
        return {name: self.generate_from_scenario(name) for name in SCENARIOS}

    def to_api_batch(self, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Convert alerts to the format expected by the Alerts API.

        Maps internal format to the AlertRequest model fields.
        """
        result = []
        for a in alerts:
            result.append({
                "timestamp": a.get("timestamp"),
                "rule_name": a.get("rule_name", "unknown"),
                "source_ip": a.get("source_ip"),
                "destination_ip": a.get("destination_ip"),
                "hostname": a.get("hostname"),
                "username": a.get("username"),
                "action": a.get("action", ""),
                "artifact": a.get("file_hash") or a.get("malware_hash"),
                "severity": a.get("severity", "medium"),
                "raw_log": json.dumps(a),
            })
        return result


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────


def main() -> None:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Generate synthetic APT attack data for AegisThreat"
    )
    parser.add_argument(
        "--scenario", "-s",
        choices=list(SCENARIOS.keys()) + ["all"],
        default="phishing-to-exfil",
        help="Attack scenario to generate",
    )
    parser.add_argument(
        "--output", "-o",
        default="",
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["raw", "api", "summary"],
        default="raw",
        help="Output format",
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List available scenarios and exit",
    )
    args = parser.parse_args()

    if args.list:
        print("Available scenarios:")
        for name, sc in SCENARIOS.items():
            print(f"  {name}: {sc['name']}")
            print(f"    TTPs: {' → '.join(sc['ttp_sequence'])}")
            print(f"    Steps: {len(sc['steps'])}")
            print()
        return

    gen = DataGenerator()

    if args.scenario == "all":
        scenarios = gen.generate_all_scenarios()
        all_alerts = []
        for name, alerts in scenarios.items():
            all_alerts.extend(alerts)
    else:
        all_alerts = gen.generate_from_scenario(args.scenario)

    if args.format == "api":
        output = json.dumps(gen.to_api_batch(all_alerts), indent=2, ensure_ascii=False)
    elif args.format == "summary":
        output = json.dumps({
            "scenario": args.scenario,
            "total_alerts": len(all_alerts),
            "time_span": {
                "start": all_alerts[0]["timestamp"] if all_alerts else None,
                "end": all_alerts[-1]["timestamp"] if all_alerts else None,
            },
            "ttp_sequence": SCENARIOS[args.scenario]["ttp_sequence"],
        }, indent=2)
    else:
        output = json.dumps(all_alerts, indent=2, ensure_ascii=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        logger.info("Wrote %d alerts to %s", len(all_alerts), args.output)
    else:
        print(output)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
