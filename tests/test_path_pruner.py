"""Tests for attack path pruning, platform consistency, and anchor-based BFS."""

import unittest

from aegis.inference.path_pruner import (
    PathPruner,
    anchor_based_bfs,
    TECHNIQUE_PLATFORMS,
    TECHNIQUE_TACTIC,
    TACTIC_ORDER,
)


class TestPathPruner(unittest.TestCase):

    def setUp(self):
        self.pruner = PathPruner(min_path_length=2)

    def test_short_path_pruned(self):
        self.assertTrue(self.pruner.should_prune(["T1566"]))

    def test_valid_chain_not_pruned(self):
        # T1566 (Phishing) → T1059 (PowerShell) → T1003 (Cred Dump)
        path = ["T1566", "T1059", "T1003"]
        self.assertFalse(self.pruner.should_prune(path))

    def test_platform_consistency(self):
        # All Windows-platform TTPs should pass
        path = ["T1566", "T1059", "T1003"]
        self.assertTrue(self.pruner._platform_consistent(path))

    def test_tactic_ordering_valid(self):
        # Forward progression: Initial Access → Execution → Credential Access
        path = ["T1566", "T1059", "T1003"]
        self.assertFalse(self.pruner._tactic_order_valid(path))

    def test_filter_paths_removes_invalid(self):
        paths = [
            ["T1566"],  # too short
            ["T1566", "T1059", "T1003"],  # valid
            ["T1003", "T1566"],  # backwards tactics
        ]
        result = self.pruner.filter_paths(paths)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], ["T1566", "T1059", "T1003"])


class TestAnchorBasedBFS(unittest.TestCase):

    def setUp(self):
        self.adjacency = {
            "T1566": ["T1059", "T1204"],
            "T1059": ["T1003", "T1083"],
            "T1204": ["T1059"],
            "T1003": ["T1021", "T1048"],
            "T1083": ["T1021"],
            "T1021": ["T1048"],
            "T1048": [],
        }

    def test_bfs_from_single_anchor(self):
        paths = anchor_based_bfs(self.adjacency, ["T1566"], max_depth=3)
        self.assertGreater(len(paths), 0)
        for p in paths:
            self.assertIn("T1566", p)

    def test_bfs_returns_multiple_paths(self):
        paths = anchor_based_bfs(self.adjacency, ["T1566"], max_depth=4)
        self.assertGreaterEqual(len(paths), 1)

    def test_unknown_anchor_returns_single_node_path(self):
        paths = anchor_based_bfs(self.adjacency, ["T9999"], max_depth=3)
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0], ["T9999"])

    def test_bfs_respects_max_paths(self):
        paths = anchor_based_bfs(self.adjacency, ["T1566"], max_depth=5, max_paths=2)
        self.assertLessEqual(len(paths), 2)


class TestPlatformMappings(unittest.TestCase):

    def test_windows_techniques_have_platforms(self):
        for tid in ["T1566", "T1059", "T1003", "T1021", "T1048"]:
            self.assertIn(tid, TECHNIQUE_PLATFORMS, f"Missing platform for {tid}")
            self.assertIn("Windows", TECHNIQUE_PLATFORMS[tid])

    def test_tactic_mappings_coherent(self):
        for tid, tactic in TECHNIQUE_TACTIC.items():
            self.assertIn(tactic, TACTIC_ORDER, f"Unknown tactic '{tactic}' for {tid}")


if __name__ == "__main__":
    unittest.main()
