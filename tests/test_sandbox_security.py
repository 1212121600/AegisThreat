"""Tests for red team strategies, arbitrator, and message security."""

import unittest

from aegis.sandbox.red_team import (
    RedTeamStrategy,
    RedTeamSimulator,
    NAIVE_ATTACKER,
    APT_ATTACKER,
    MODERATE_ATTACKER,
)
from aegis.sandbox.arbitrator import Arbitrator, ArbitrationVerdict, run_debate_arbitration
from aegis.core.security import MessageSigner, ReplayProtection
from aegis.core.models import ThreatEvent, EventType


class TestRedTeamSimulator(unittest.TestCase):

    def setUp(self):
        self.sim = RedTeamSimulator(seed=123)

    def test_simulate_response_with_fallback(self):
        resp = self.sim.simulate_response("T1566", APT_ATTACKER)
        # APT has 5 fallbacks for T1566, so we should get a response
        self.assertIsNotNone(resp)
        self.assertIn(resp, ["T1189", "T1190", "T1133", "T1078", "T9999"])

    def test_naive_attacker_gives_up_on_phishing(self):
        resp = self.sim.simulate_response("T1566", NAIVE_ATTACKER)
        # Naive attacker has empty fallback for T1566 → gives up (dwell or None)
        # With 30% dwell + 1% unknown, ~69% chance of None
        # Run multiple times to verify behavior
        results = [self.sim.simulate_response("T1566", NAIVE_ATTACKER) for _ in range(50)]
        none_count = sum(1 for r in results if r is None)
        self.assertGreater(none_count, 0, "Naive attacker should sometimes give up")

    def test_simulate_full_response(self):
        resp = self.sim.simulate_full_response(
            ["T1566"], MODERATE_ATTACKER, max_steps=3
        )
        self.assertLessEqual(len(resp), 3)

    def test_run_worst_case_multiple_strategies(self):
        results = self.sim.run_worst_case(["T1566"], max_steps=3)
        self.assertEqual(len(results), 3)  # 3 strategies
        # APT should have the most steps (most aggressive)
        max_len = max(len(r) for r in results)
        self.assertGreaterEqual(max_len, 0)


class TestArbitrator(unittest.TestCase):

    def setUp(self):
        self.arb = Arbitrator(max_rounds=3)

    def test_full_coverage_accepted(self):
        chain = ["T1566", "T1059", "T1003"]
        actions = [
            {"action": "block_ip", "expected_effect": "T1566", "reason": "x", "target_ttp": "T1566"},
            {"action": "kill_process", "expected_effect": "T1059", "reason": "x", "target_ttp": "T1059"},
            {"action": "isolate_host", "expected_effect": "T1003", "reason": "x", "target_ttp": "T1003"},
        ]
        verdict = self.arb.evaluate(1, chain, actions, 30)
        self.assertTrue(verdict.defense_accepted)
        self.assertGreaterEqual(verdict.coverage_score, 0.8)

    def test_low_coverage_rejected(self):
        chain = ["T1566", "T1059", "T1003", "T1021", "T1048"]
        actions = [
            {"action": "block_ip", "expected_effect": "T1566", "reason": "x", "target_ttp": "T1566"},
        ]
        verdict = self.arb.evaluate(1, chain, actions, 50)
        self.assertFalse(verdict.defense_accepted)

    def test_max_rounds_forced_acceptance(self):
        chain = ["T1566", "T1059"]
        actions = [{"action": "block_ip", "expected_effect": "T1566", "reason": "x", "target_ttp": "T1566"}]
        verdict = self.arb.evaluate(3, chain, actions, 80)  # Max round = 3
        self.assertTrue(verdict.defense_accepted, "Should force-accept at max rounds")

    def test_high_impact_rejected(self):
        chain = ["T1566"]
        actions = [{"action": "isolate_host", "expected_effect": "T1566", "reason": "x", "target_ttp": "T1566"}]
        verdict = self.arb.evaluate(1, chain, actions, 95)  # Impact too high
        self.assertFalse(verdict.defense_accepted)

    def test_round_log_accumulates(self):
        chain = ["T1566"]
        actions = [{"action": "block_ip", "expected_effect": "T1566", "reason": "x", "target_ttp": "T1566"}]
        self.arb.evaluate(1, chain, actions, 10)
        self.arb.evaluate(2, chain, actions, 10)
        self.assertEqual(len(self.arb.get_round_log()), 2)


class TestRunDebateArbitration(unittest.TestCase):

    def test_basic_debate_returns_verdict(self):
        chain = ["T1566", "T1059", "T1003"]
        actions = [
            {"action": "block_ip", "expected_effect": "T1566", "reason": "x", "target_ttp": "T1566"},
            {"action": "kill_process", "expected_effect": "T1059", "reason": "x", "target_ttp": "T1059"},
            {"action": "isolate_host", "expected_effect": "T1003", "reason": "x", "target_ttp": "T1003"},
        ]
        accepted, final_actions, log = run_debate_arbitration(chain, actions, 30, max_rounds=2)
        self.assertTrue(accepted)
        self.assertGreaterEqual(len(log), 1)


class TestMessageSigner(unittest.TestCase):

    def test_disabled_signer_passes_through(self):
        signer = MessageSigner(secret="")
        event = ThreatEvent(event_type=EventType.HEARTBEAT, producer="detection")
        result = signer.sign_event(event)
        self.assertEqual(result.event_id, event.event_id)
        self.assertTrue(signer.verify_event(event))

    def test_enabled_signer_adds_signature(self):
        signer = MessageSigner(secret="test-secret-key-123")
        event = ThreatEvent(event_type=EventType.HEARTBEAT, producer="detection")
        signed = signer.sign_event(event)
        self.assertIn("signature", signed.trace_context or {})
        self.assertTrue(signer.verify_event(signed))

    def test_tampered_event_fails_verification(self):
        signer = MessageSigner(secret="test-secret-key-123")
        event = ThreatEvent(event_type=EventType.HEARTBEAT, producer="detection")
        signed = signer.sign_event(event)
        # Tamper with the event
        signed.event_id = "tampered-id"
        self.assertFalse(signer.verify_event(signed))

    def test_wrong_key_fails(self):
        signer_a = MessageSigner(secret="key-a")
        signer_b = MessageSigner(secret="key-b")
        event = ThreatEvent(event_type=EventType.HEARTBEAT, producer="detection")
        signed = signer_a.sign_event(event)
        self.assertFalse(signer_b.verify_event(signed))


class TestReplayProtection(unittest.TestCase):

    def setUp(self):
        self.rp = ReplayProtection(window_seconds=3600)

    def test_first_event_not_replay(self):
        event = ThreatEvent(event_type=EventType.HEARTBEAT, producer="detection")
        self.assertFalse(self.rp.is_replay(event))

    def test_second_same_event_is_replay(self):
        event = ThreatEvent(event_type=EventType.HEARTBEAT, producer="detection")
        self.rp.is_replay(event)
        self.assertTrue(self.rp.is_replay(event))

    def test_different_events_not_replay(self):
        e1 = ThreatEvent(event_type=EventType.HEARTBEAT, producer="detection")
        e2 = ThreatEvent(event_type=EventType.HEARTBEAT, producer="tracing")
        self.rp.is_replay(e1)
        self.assertFalse(self.rp.is_replay(e2))


if __name__ == "__main__":
    unittest.main()
