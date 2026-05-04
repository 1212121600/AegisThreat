"""Integration tests for the full AegisThreat agent workflow.

Tests the end-to-end pipeline:
  Synthetic Alert → Detection Agent → Fragment → Tracing Agent → Chain → Defense Agent → Decision
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from aegis.core.bus import InMemoryBus, Topics
from aegis.core.models import (
    AttackChain,
    AttackFragment,
    DecisionScript,
    EventType,
    ThreatEvent,
)
from aegis.agents.detection import DetectionAgent
from aegis.agents.tracing import TracingAgent
from aegis.agents.defense import DefenseAgent


class TestAgentWorkflow(unittest.TestCase):
    """Test the full Detection → Tracing → Defense pipeline."""

    def setUp(self) -> None:
        self.bus = InMemoryBus()

        # Collected outputs
        self.fragments: list[AttackFragment] = []
        self.chains: list[AttackChain] = []
        self.decisions: list[DecisionScript] = []

        # Subscribe to collect outputs
        self.bus.subscribe(Topics.FRAGMENT, self._on_fragment)
        self.bus.subscribe(Topics.CHAIN, self._on_chain)
        self.bus.subscribe(Topics.DECISION, self._on_decision)

        # Create agents with shared bus
        self.detection = DetectionAgent(bus=self.bus)
        self.tracing = TracingAgent(bus=self.bus)
        self.defense = DefenseAgent(bus=self.bus)

        self.detection.start()
        self.tracing.start()
        self.defense.start()

    def tearDown(self) -> None:
        self.defense.stop()
        self.tracing.stop()
        self.detection.stop()

    def _on_fragment(self, event: ThreatEvent) -> None:
        frag = AttackFragment(**event.payload) if isinstance(event.payload, dict) else event.payload
        self.fragments.append(frag)

    def _on_chain(self, event: ThreatEvent) -> None:
        chain = AttackChain(**event.payload) if isinstance(event.payload, dict) else event.payload
        self.chains.append(chain)

    def _on_decision(self, event: ThreatEvent) -> None:
        dec = DecisionScript(**event.payload) if isinstance(event.payload, dict) else event.payload
        self.decisions.append(dec)

    # ── Tests ────────────────────────────────

    def test_detection_agent_generates_fragment(self) -> None:
        """Detection Agent should generate a Fragment from clustered alerts."""
        base_time = datetime.now(timezone.utc)
        alerts = [
            {"timestamp": base_time.isoformat(), "rule_name": "brute_force", "source_ip": "1.2.3.4", "destination_ip": "10.0.0.5", "action": "failed login attempt 1", "severity": "high"},
            {"timestamp": base_time.isoformat(), "rule_name": "brute_force", "source_ip": "1.2.3.4", "destination_ip": "10.0.0.5", "action": "failed login attempt 2", "severity": "high"},
            {"timestamp": base_time.isoformat(), "rule_name": "brute_force_success", "source_ip": "1.2.3.4", "destination_ip": "10.0.0.5", "action": "successful login", "severity": "critical", "username": "admin"},
        ]

        fragment = None
        for alert in alerts:
            fragment = self.detection.ingest_and_publish(alert)

        self.assertIsNotNone(fragment, "Should generate a fragment from 3 brute force alerts")
        self.assertGreaterEqual(fragment.confidence, 0.5)
        self.assertIn("T1110", [t.technique_id for t in fragment.suspected_ttps])
        self.assertEqual(len(self.fragments), 1)

    def test_detection_agent_insufficient_alerts(self) -> None:
        """Detection Agent should NOT generate a Fragment with too few alerts."""
        base_time = datetime.now(timezone.utc)
        alert = {"timestamp": base_time.isoformat(), "rule_name": "brute_force", "source_ip": "1.2.3.4", "action": "single attempt", "severity": "low"}

        fragment = self.detection.ingest_and_publish(alert)
        self.assertIsNone(fragment, "Single alert should not trigger fragment")
        self.assertEqual(len(self.fragments), 0)

    def test_tracing_agent_produces_chain(self) -> None:
        """Tracing Agent should produce an AttackChain from an AttackFragment."""
        fragment = AttackFragment(
            entities=[],
            summary="Brute force followed by successful login",
            suspected_ttps=[{"technique_id": "T1110", "technique_name": "Brute Force", "confidence": 0.9, "evidence": "500 failed attempts"}],
            confidence=0.85,
            confidence_level="high",
            timestamp_span=(datetime.now(timezone.utc), datetime.now(timezone.utc)),
            raw_alert_count=5,
        )
        # Fix: TTPMapping objects
        from aegis.core.models import TTPMapping
        fragment.suspected_ttps = [TTPMapping(technique_id="T1110", technique_name="Brute Force", confidence=0.9, evidence="500 attempts")]

        self.tracing.on_fragment(fragment, correlation_id=None)

        self.assertGreaterEqual(len(self.chains), 1, "Should produce at least one chain")
        chain = self.chains[0]
        self.assertIn("T1110", [n.technique_id for n in chain.nodes])
        self.assertGreaterEqual(chain.step_count, 1)
        self.assertGreater(len(chain.predicted_next_steps), 0, "Should predict next steps")

    def test_defense_agent_produces_decision(self) -> None:
        """Defense Agent should produce a DecisionScript from an AttackChain."""
        from aegis.core.models import ChainNode, ChainEdge

        chain = AttackChain(
            fragment_id="test-frag-001",
            nodes=[
                ChainNode(step=0, technique_id="T1566", technique_name="Phishing", tactic="Initial Access", description="Phishing email delivered", confidence=0.9),
                ChainNode(step=1, technique_id="T1059", technique_name="PowerShell", tactic="Execution", description="Macro executed PowerShell", confidence=0.85),
                ChainNode(step=2, technique_id="T1071", technique_name="C2 Channel", tactic="Command & Control", description="HTTPS beacon established", confidence=0.8),
            ],
            edges=[
                ChainEdge(from_step=0, to_step=1),
                ChainEdge(from_step=1, to_step=2),
            ],
            overall_confidence=0.85,
        )

        decision = self.defense.generate_decision(chain)
        self.assertIsNotNone(decision, "Should produce a decision")
        self.assertGreaterEqual(decision.step_count, 1, "Should have at least one defensive action")
        self.assertTrue(decision.requires_human_approval, "Decisions should require human approval by default")
        self.assertGreater(decision.business_impact.score, 0, "Should estimate business impact")

    def test_full_pipeline_integration(self) -> None:
        """Full end-to-end: synthetic alerts → fragment → chain → decision."""
        base_time = datetime.now(timezone.utc)

        # Simulate a phishing scenario (minimal 5 alerts)
        alerts = [
            {"timestamp": base_time.isoformat(), "rule_name": "phishing", "source_ip": "45.67.89.10", "destination_ip": "10.0.0.5", "action": "phishing email with attachment", "severity": "high"},
            {"timestamp": base_time.isoformat(), "rule_name": "macro_execution", "source_ip": "10.0.0.5", "action": "Word macro executed", "severity": "critical", "hostname": "ws-01.corp.local", "username": "jdoe"},
            {"timestamp": base_time.isoformat(), "rule_name": "c2_communication", "source_ip": "10.0.0.5", "action": "HTTPS beacon to suspicious domain", "severity": "critical", "hostname": "ws-01.corp.local", "domain": "bad-c2.net"},
            {"timestamp": base_time.isoformat(), "rule_name": "credential_dump", "source_ip": "10.0.0.5", "action": "LSASS memory access", "severity": "critical", "hostname": "ws-01.corp.local"},
            {"timestamp": base_time.isoformat(), "rule_name": "data_exfil", "source_ip": "10.0.0.5", "action": "Large HTTPS upload to external IP", "severity": "critical", "hostname": "ws-01.corp.local", "destination_ip": "185.220.101.34"},
        ]

        # Feed alerts
        for alert in alerts:
            self.detection.ingest_and_publish(alert)

        # Check fragment was produced
        self.assertGreaterEqual(len(self.fragments), 1, "Should produce a fragment from 5 alerts")
        frag = self.fragments[0]
        self.assertIn("T1566", [t.technique_id for t in frag.suspected_ttps], "Should detect phishing TTP")

        # Check chain was produced (tracing agent subscribes to fragments)
        self.assertGreaterEqual(len(self.chains), 1, "Should produce a chain from the fragment")
        chain = self.chains[0]
        self.assertGreaterEqual(chain.step_count, 2, "Chain should have at least 2 steps")

        # Check decision was produced (defense agent subscribes to chains)
        self.assertGreaterEqual(len(self.decisions), 1, "Should produce a decision from the chain")
        decision = self.decisions[0]
        self.assertGreaterEqual(decision.step_count, 1, "Decision should have at least 1 action")
        self.assertTrue(decision.requires_human_approval)

    def test_bus_pub_sub(self) -> None:
        """Test basic message bus publish/subscribe."""
        received: list[ThreatEvent] = []

        def handler(event: ThreatEvent) -> None:
            received.append(event)

        self.bus.subscribe("test.topic", handler)
        event = ThreatEvent(event_type=EventType.HEARTBEAT, producer="detection")
        self.bus.publish("test.topic", event)

        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].event_id, event.event_id)

    def test_synthetic_data_generator(self) -> None:
        """Test the synthetic data generator produces valid alert sequences."""
        from tools.data_generator import DataGenerator

        gen = DataGenerator()
        alerts = gen.generate_from_scenario("phishing-to-exfil")

        self.assertGreaterEqual(len(alerts), 5, "Should generate at least 5 alerts for phishing-to-exfil")
        self.assertTrue(all("timestamp" in a for a in alerts), "All alerts should have timestamps")
        self.assertTrue(all("rule_name" in a for a in alerts), "All alerts should have rule names")

        # Timestamps should be in order
        timestamps = [a["timestamp"] for a in alerts]
        self.assertEqual(timestamps, sorted(timestamps), "Alerts should be chronologically ordered")


if __name__ == "__main__":
    unittest.main()
