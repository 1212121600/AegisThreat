"""Red Team strategy library for MCTS attacker simulation.

Solves: the MCTS defender-vs-attacker simulation in the Defense Agent needs
an independent attacker model, not one derived from the same Tracing Agent
that produced the chain (which creates circular self-validation).

This module provides attack strategy profiles independent of the defense logic.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class RedTeamStrategy:
    """A specific attacker behavior profile.

    Each strategy defines what the attacker will do when their current TTP
    is blocked by a defensive action. Different strategies model different
    levels of attacker sophistication.
    """

    name: str
    description: str

    # When blocked at technique T, what alternative technique do they try?
    # Maps blocked_TTP → list of alternative TTPs (ordered by likelihood)
    fallback_map: dict[str, list[str]] = field(default_factory=dict)

    # Probability of using a technique NOT in ATT&CK (unknown/0-day)
    unknown_ttp_probability: float = 0.05

    # Probability of waiting/going silent after a block (dwell)
    dwell_probability: float = 0.15


# ──────────────────────────────────────────────
# Pre-defined Red Team Profiles
# ──────────────────────────────────────────────


# Optimistic (naive attacker — best case for defense)
NAIVE_ATTACKER = RedTeamStrategy(
    name="Naive Attacker",
    description="Low-sophistication attacker using only known TTPs. "
                "When blocked, tries one obvious fallback or gives up.",
    fallback_map={
        "T1566": [],  # If phishing is blocked, gives up initial access
        "T1059": ["T1203"],  # If PS blocked, try client exploit (unlikely)
        "T1021": ["T1570"],  # If remote services blocked, try tool transfer
        "T1071": [],  # If C2 blocked, no fallback
    },
    unknown_ttp_probability=0.01,
    dwell_probability=0.30,  # Naive attacker dwells longer
)

# Pessimistic (sophisticated APT — worst case for defense)
APT_ATTACKER = RedTeamStrategy(
    name="Sophisticated APT Attacker",
    description="Well-resourced APT group with multiple toolsets. "
                "When blocked, pivots to alternative TTPs seamlessly.",
    fallback_map={
        "T1566": ["T1189", "T1190", "T1133", "T1078"],
        "T1204": ["T1059", "T1203"],
        "T1059": ["T1203", "T1210", "T1027"],
        "T1071": ["T1573", "T1105", "T1567"],
        "T1003": ["T1110", "T1552", "T1555"],
        "T1021": ["T1570", "T1563", "T1210", "T1083"],
        "T1547": ["T1053", "T1505", "T1543"],
        "T1562": ["T1027", "T1070", "T1036"],
        "T1048": ["T1567", "T1537", "T1020"],
    },
    unknown_ttp_probability=0.10,
    dwell_probability=0.05,  # APT doesn't wait long
)

# Realistic (moderate attacker — baseline for MCTS)
MODERATE_ATTACKER = RedTeamStrategy(
    name="Moderate Attacker",
    description="Competent attacker with some fallback options but "
                "not unlimited resources.",
    fallback_map={
        "T1566": ["T1189", "T1078"],
        "T1204": ["T1059"],
        "T1059": ["T1203"],
        "T1071": ["T1573", "T1105"],
        "T1003": ["T1110"],
        "T1021": ["T1570", "T1210"],
        "T1547": ["T1053"],
        "T1562": ["T1027"],
        "T1048": ["T1567"],
    },
    unknown_ttp_probability=0.05,
    dwell_probability=0.10,
)

# All strategies available for MCTS simulation
ALL_STRATEGIES = [NAIVE_ATTACKER, MODERATE_ATTACKER, APT_ATTACKER]


class RedTeamSimulator:
    """Simulate attacker responses to defensive actions during MCTS.

    This is the independent attacker model — it does NOT use the Tracing Agent
    for predictions. Instead, it uses pre-defined strategy profiles with
    probabilistic behavior.
    """

    def __init__(
        self,
        strategies: Optional[list[RedTeamStrategy]] = None,
        seed: int = 42,
    ) -> None:
        self._strategies = strategies or ALL_STRATEGIES
        self._rng = random.Random(seed)

    def simulate_response(
        self,
        blocked_ttp: str,
        strategy: RedTeamStrategy,
        adjacency: Optional[dict[str, list[str]]] = None,
    ) -> Optional[str]:
        """Simulate what TTP the attacker tries next after being blocked.

        Args:
            blocked_ttp: The TTP that was just blocked by defense.
            strategy: The attacker strategy profile to use.
            adjacency: Optional ATT&CK adjacency map for additional options.

        Returns:
            Next TTP the attacker will try, or None if they give up/dwell.
        """
        # Chance of dwelling (attacker goes silent)
        if self._rng.random() < strategy.dwell_probability:
            return None

        # Chance of unknown/0-day TTP
        if self._rng.random() < strategy.unknown_ttp_probability:
            return "T9999"  # Sentinel for unknown TTP

        # Check fallback map
        fallbacks = strategy.fallback_map.get(blocked_ttp, [])
        if fallbacks:
            return self._rng.choice(fallbacks)

        # If no defined fallback, check general adjacency
        if adjacency and blocked_ttp in adjacency:
            options = adjacency[blocked_ttp]
            if options:
                return self._rng.choice(options)

        return None  # Attacker has no more moves

    def simulate_full_response(
        self,
        blocked_ttps: list[str],
        strategy: RedTeamStrategy,
        max_steps: int = 5,
        adjacency: Optional[dict[str, list[str]]] = None,
    ) -> list[str]:
        """Simulate a multi-step attacker response to a sequence of blocks.

        Returns the list of TTPs the attacker would try in response.
        """
        responses: list[str] = []
        current = blocked_ttps[-1] if blocked_ttps else ""

        for _ in range(max_steps):
            next_ttp = self.simulate_response(current, strategy, adjacency)
            if next_ttp is None:
                break
            responses.append(next_ttp)
            current = next_ttp

        return responses

    def run_worst_case(
        self,
        blocked_ttps: list[str],
        adjacency: Optional[dict[str, list[str]]] = None,
        max_steps: int = 5,
    ) -> list[list[str]]:
        """Run simulation against all strategies and return the worst cases.

        "Worst case" = the attacker that advances the furthest.
        """
        results: list[list[str]] = []
        for strategy in self._strategies:
            resp = self.simulate_full_response(blocked_ttps, strategy, max_steps, adjacency)
            results.append(resp)
        return results
