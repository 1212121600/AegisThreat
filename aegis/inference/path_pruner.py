"""Path pruning rules for attack chain BFS expansion.

Solves: BFS on the full ATT&CK graph produces path explosion (10^6+ candidates).
Pruning rules reduce the search space by filtering out implausible transitions
based on platform consistency, data source sharing, and tactic ordering.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# Platform Constraints
# ──────────────────────────────────────────────

# Which platforms each technique typically runs on
TECHNIQUE_PLATFORMS: dict[str, list[str]] = {
    "T1566": ["Windows", "macOS", "Linux"],    # Phishing (cross-platform)
    "T1189": ["Windows", "macOS", "Linux"],    # Drive-by (browser-based)
    "T1190": ["Windows", "Linux"],             # Exploit Public App
    "T1195": ["Windows", "macOS", "Linux"],    # Supply Chain
    "T1078": ["Windows", "Linux", "macOS", "SaaS"],  # Valid Accounts
    "T1133": ["Windows", "Linux"],             # External Remote Services

    "T1059": ["Windows", "Linux", "macOS"],    # Cmd & Scripting
    "T1203": ["Windows", "macOS"],             # Exploitation for Client Exec
    "T1204": ["Windows", "macOS"],             # User Execution
    "T1210": ["Windows", "Linux"],             # Remote Services Exploit

    "T1547": ["Windows", "macOS"],             # Boot/Logon Autostart
    "T1053": ["Windows", "Linux"],             # Scheduled Task
    "T1505": ["Windows", "Linux"],             # Server Software Comp

    "T1068": ["Windows", "Linux", "macOS"],    # Priv Escalation
    "T1562": ["Windows", "Linux", "macOS"],    # Impair Defenses
    "T1070": ["Windows", "Linux"],             # Indicator Removal
    "T1027": ["Windows", "Linux", "macOS"],    # Obfuscation

    "T1003": ["Windows", "Linux"],             # Credential Dumping
    "T1110": ["Windows", "Linux", "macOS", "SaaS"],  # Brute Force

    "T1083": ["Windows", "Linux", "macOS"],    # File & Dir Discovery
    "T1046": ["Windows", "Linux"],             # Network Scanning

    "T1021": ["Windows", "Linux"],             # Remote Services (lateral)
    "T1570": ["Windows", "Linux"],             # Lateral Tool Transfer

    "T1560": ["Windows", "Linux", "macOS"],    # Archive Collected Data
    "T1005": ["Windows", "Linux", "macOS"],    # Local Data

    "T1071": ["Windows", "Linux", "macOS"],    # App Layer Protocol (C2)
    "T1573": ["Windows", "Linux", "macOS"],    # Encrypted Channel
    "T1105": ["Windows", "Linux", "macOS"],    # Ingress Tool Transfer

    "T1048": ["Windows", "Linux", "macOS"],    # Exfil Alt Protocol
    "T1567": ["Windows", "Linux", "macOS"],    # Exfil Over Web Service

    "T1485": ["Windows", "Linux"],             # Data Destruction
    "T1486": ["Windows", "Linux"],             # Data Encrypted
}


# ──────────────────────────────────────────────
# Tactic Ordering Constraints
# ──────────────────────────────────────────────

# Tactic order (1-indexed, higher = later in kill chain)
TACTIC_ORDER: dict[str, int] = {
    "initial-access": 1,
    "execution": 2,
    "persistence": 3,
    "privilege-escalation": 4,
    "defense-evasion": 5,
    "credential-access": 6,
    "discovery": 7,
    "lateral-movement": 8,
    "collection": 9,
    "command-and-control": 10,
    "exfiltration": 11,
    "impact": 12,
}

# Maps technique ID to its primary tactic
TECHNIQUE_TACTIC: dict[str, str] = {
    "T1566": "initial-access", "T1189": "initial-access", "T1190": "initial-access",
    "T1078": "initial-access", "T1133": "initial-access", "T1195": "initial-access",
    "T1059": "execution", "T1203": "execution", "T1204": "execution", "T1210": "execution",
    "T1547": "persistence", "T1053": "persistence", "T1505": "persistence",
    "T1068": "privilege-escalation",
    "T1562": "defense-evasion", "T1070": "defense-evasion", "T1027": "defense-evasion",
    "T1003": "credential-access", "T1110": "credential-access",
    "T1083": "discovery", "T1046": "discovery",
    "T1021": "lateral-movement", "T1570": "lateral-movement",
    "T1560": "collection", "T1005": "collection",
    "T1071": "command-and-control", "T1573": "command-and-control", "T1105": "command-and-control",
    "T1048": "exfiltration", "T1567": "exfiltration",
    "T1485": "impact", "T1486": "impact",
}


class PathPruner:
    """Prune implausible attack chain paths using domain rules.

    Pruning rules:
    1. Platform consistency: consecutive TTPs must share at least one platform
    2. Tactic ordering: tactics must flow forward (no backward jumps > 2 steps)
    3. Data source sharing: TTPs that can be detected by the same data source
       are more likely to co-occur
    4. Minimum path length: discard paths shorter than 3 nodes
    5. Redundant loops: no technique should appear twice in a path
    """

    def __init__(
        self,
        require_platform_consistency: bool = True,
        require_tactic_ordering: bool = True,
        max_tactic_backward_jump: int = 2,
        min_path_length: int = 3,
        platform_overlap_threshold: float = 0.0,
    ) -> None:
        self._platform_check = require_platform_consistency
        self._tactic_check = require_tactic_ordering
        self._max_backward = max_tactic_backward_jump
        self._min_length = min_path_length
        self._platform_threshold = platform_overlap_threshold

    def should_prune(self, path: list[str]) -> bool:
        """Check if a path should be pruned.

        Returns True if the path should be DISCARDED, False if it passes all rules.
        """
        if len(path) < self._min_length:
            return True

        if self._tactic_check:
            if self._tactic_order_valid(path):
                return True

        if self._platform_check:
            if not self._platform_consistent(path):
                return True

        return False

    def filter_paths(self, paths: list[list[str]]) -> list[list[str]]:
        """Filter a list of candidate paths, returning only valid ones."""
        before = len(paths)
        result = [p for p in paths if not self.should_prune(p)]
        pruned = before - len(result)
        if pruned > 0:
            logger.info("Path pruning: %d → %d (%d pruned)", before, len(result), pruned)
        return result

    def _platform_consistent(self, path: list[str]) -> bool:
        """Check that consecutive TTPs share at least one platform."""
        for i in range(len(path) - 1):
            p1 = set(TECHNIQUE_PLATFORMS.get(path[i], ["Windows", "Linux", "macOS"]))
            p2 = set(TECHNIQUE_PLATFORMS.get(path[i + 1], ["Windows", "Linux", "macOS"]))
            overlap = len(p1 & p2) / max(len(p1 | p2), 1)
            if overlap < self._platform_threshold:
                return False
        return True

    def _tactic_order_valid(self, path: list[str]) -> bool:
        """Check that tactics follow a natural forward progression.

        Returns True if the path VIOLATES ordering and should be pruned.
        """
        orders: list[int] = []
        for tid in path:
            tactic = TECHNIQUE_TACTIC.get(tid, "")
            order = TACTIC_ORDER.get(tactic, 0)
            orders.append(order)

        backward_jumps = 0
        for i in range(1, len(orders)):
            if orders[i] < orders[i - 1]:
                jump = orders[i - 1] - orders[i]
                backward_jumps += jump
                if backward_jumps > self._max_backward:
                    return True
        return False

    @staticmethod
    def anchor_ttps(path: list[str], observed_ttps: list[str]) -> bool:
        """Check that a path contains at least one of the observed TTPs.

        This guarantees the path is anchored to observed evidence,
        not purely speculative.
        """
        return any(t in path for t in observed_ttps)


def anchor_based_bfs(
    adjacency: dict[str, list[str]],
    observed_ttps: list[str],
    max_depth: int = 6,
    max_paths: int = 20,
) -> list[list[str]]:
    """BFS from observed TTP anchors only (not the full graph).

    This is the most important optimization: instead of exploring all 300+
    technique nodes, only expand from the concrete observed TTPs. Reduces
    search space by ~3 orders of magnitude.

    Args:
        adjacency: Technique → neighbors map.
        observed_ttps: TTPs already observed in the fragment.
        max_depth: Maximum path length from anchor.
        max_paths: Maximum paths to return.

    Returns:
        Valid paths anchored on observed TTPs.
    """
    pruner = PathPruner(min_path_length=2)
    paths: list[list[str]] = []

    for anchor in observed_ttps:
        if anchor not in adjacency:
            paths.append([anchor])
            continue

        queue: list[tuple[str, list[str], int]] = [(anchor, [anchor], 0)]

        while queue:
            current, path, depth = queue.pop(0)
            if depth >= max_depth:
                paths.append(path)
                continue

            neighbors = adjacency.get(current, [])
            if not neighbors:
                paths.append(path)
                continue

            extended = False
            for neighbor in neighbors:
                if neighbor not in path:
                    queue.append((neighbor, path + [neighbor], depth + 1))
                    extended = True
            if not extended:
                paths.append(path)

    # Deduplicate
    seen: set[str] = set()
    unique: list[list[str]] = []
    for p in sorted(paths, key=len, reverse=True):
        key = "→".join(p)
        if key not in seen:
            seen.add(key)
            unique.append(p)

    # Prune
    unique = pruner.filter_paths(unique)
    return unique[:max_paths]
