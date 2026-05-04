"""Tests for alert deduplication, severity filtering, and schema normalisation."""

import unittest
from datetime import datetime, timezone

from aegis.core.alert_dedup import AlertDeduplicator, SeverityFilter, AlertNormaliser, TwoStageClusterer


class TestAlertDeduplicator(unittest.TestCase):

    def setUp(self):
        self.dedup = AlertDeduplicator(window_seconds=300)

    def test_first_alert_not_duplicate(self):
        alert = {"source_ip": "1.2.3.4", "destination_ip": "10.0.0.1", "action": "login", "rule_name": "brute_force"}
        self.assertFalse(self.dedup.is_duplicate(alert))

    def test_duplicate_detected(self):
        alert = {"source_ip": "1.2.3.4", "destination_ip": "10.0.0.1", "action": "login", "rule_name": "brute_force"}
        self.dedup.is_duplicate(alert)
        self.assertTrue(self.dedup.is_duplicate(alert))

    def test_different_fields_not_duplicate(self):
        a1 = {"source_ip": "1.2.3.4", "destination_ip": "10.0.0.1", "action": "login", "rule_name": "brute_force"}
        a2 = {"source_ip": "5.6.7.8", "destination_ip": "10.0.0.1", "action": "login", "rule_name": "brute_force"}
        self.dedup.is_duplicate(a1)
        self.assertFalse(self.dedup.is_duplicate(a2))

    def test_filter_alerts_removes_duplicates(self):
        alerts = [
            {"source_ip": "1.2.3.4", "destination_ip": "10.0.0.1", "action": "a", "rule_name": "r1"},
            {"source_ip": "1.2.3.4", "destination_ip": "10.0.0.1", "action": "a", "rule_name": "r1"},
            {"source_ip": "5.6.7.8", "destination_ip": "10.0.0.1", "action": "b", "rule_name": "r2"},
        ]
        result = self.dedup.filter_alerts(alerts)
        self.assertEqual(len(result), 2)

    def test_reset_clears_seen(self):
        alert = {"source_ip": "1.2.3.4", "destination_ip": "10.0.0.1", "action": "login", "rule_name": "brute_force"}
        self.dedup.is_duplicate(alert)
        self.dedup.reset()
        self.assertFalse(self.dedup.is_duplicate(alert))


class TestSeverityFilter(unittest.TestCase):

    def test_critical_passes(self):
        f = SeverityFilter(min_severity="medium")
        self.assertTrue(f.should_process({"severity": "critical"}))

    def test_low_blocked_at_medium_threshold(self):
        f = SeverityFilter(min_severity="medium")
        self.assertFalse(f.should_process({"severity": "low"}))

    def test_filter_alerts_batch(self):
        f = SeverityFilter(min_severity="high")
        alerts = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
        ]
        result = f.filter_alerts(alerts)
        self.assertEqual(len(result), 2)


class TestAlertNormaliser(unittest.TestCase):

    def test_splunk_normalisation(self):
        raw = {"_time": "2026-05-04T10:00:00Z", "src_ip": "1.2.3.4",
               "dest_ip": "10.0.0.5", "host": "server01", "user": "admin",
               "signature": "Brute Force Detected", "severity": "high",
               "rule_name": "brute_force_rule"}
        n = AlertNormaliser.normalise(raw, "splunk")
        self.assertEqual(n["source_ip"], "1.2.3.4")
        self.assertEqual(n["destination_ip"], "10.0.0.5")
        self.assertEqual(n["hostname"], "server01")
        self.assertEqual(n["username"], "admin")
        self.assertEqual(n["_source"], "splunk")

    def test_sentinel_one_normalisation(self):
        raw = {"detectedAt": "2026-05-04T10:00:00Z", "sourceIp": "5.6.7.8",
               "targetIp": "10.0.0.5", "computerName": "ep-win10-01",
               "user": "jdoe", "threatName": "Mimikatz", "severity": "critical"}
        n = AlertNormaliser.normalise(raw, "sentinel_one")
        self.assertEqual(n["source_ip"], "5.6.7.8")
        self.assertEqual(n["destination_ip"], "10.0.0.5")
        self.assertEqual(n["hostname"], "ep-win10-01")

    def test_suricata_normalisation(self):
        raw = {"timestamp": "2026-05-04T10:00:00Z", "src_ip": "10.0.0.1",
               "dest_ip": "192.168.1.1", "alert.signature": "ET EXPLOIT",
               "alert.severity": "high"}
        n = AlertNormaliser.normalise(raw, "suricata")
        self.assertEqual(n["source_ip"], "10.0.0.1")
        self.assertEqual(n["action"], "ET EXPLOIT")
        self.assertEqual(n["severity"], "high")

    def test_unknown_source_preserves_fields(self):
        raw = {"source_ip": "1.2.3.4", "custom_field": "value"}
        n = AlertNormaliser.normalise(raw, "unknown")
        self.assertEqual(n["source_ip"], "1.2.3.4")
        self.assertIn("custom_field", n["_raw"])


class TestTwoStageClusterer(unittest.TestCase):

    def setUp(self):
        self.clusterer = TwoStageClusterer(min_severity="medium")

    def test_prefilter_removes_low_severity_and_duplicates(self):
        alerts = [
            {"severity": "critical", "source_ip": "1.2.3.4", "destination_ip": "10.0.0.1", "action": "a", "rule_name": "r1"},
            {"severity": "critical", "source_ip": "1.2.3.4", "destination_ip": "10.0.0.1", "action": "a", "rule_name": "r1"},
            {"severity": "low", "source_ip": "5.6.7.8", "destination_ip": "10.0.0.1", "action": "b", "rule_name": "r2"},
            {"severity": "high", "source_ip": "9.9.9.9", "destination_ip": "10.0.0.1", "action": "c", "rule_name": "r3"},
        ]
        result = self.clusterer.prefilter(alerts)
        self.assertEqual(len(result), 2)  # 1 dedup + 1 low removed = 2 remaining
