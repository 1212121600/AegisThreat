"""Bayesian network for attack chain probability inference (Phase 2).

Models the conditional probability of each TTP given prior TTPs in the chain,
incorporating:
- Detection frequency of each TTP in the target environment
- Threat intelligence prevalence scores
- Historical attack case transition probabilities

Dependencies (Phase 2): pgmpy or custom Bayesian implementation
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


class BayesianNetwork:
    """Bayesian network for attack chain probability estimation.

    Phase 1: Not used (heuristic confidence scoring in the MVP).
    Phase 2: Builds CPTs from ATT&CK adjacency weights, detection coverage,
             and threat intel to compute joint probability of observed chain.
    """

    def __init__(self) -> None:
        self._cpts: dict[str, dict[str, float]] = {}  # node → {parent_state: prob}
        self._priors: dict[str, float] = {}  # technique_id → prior probability
        self._trained = False

    def load_from_attck(self, adjacency: dict[str, list[str]], edge_weights: Optional[dict[str, float]] = None) -> None:
        """Initialize the Bayesian network from ATT&CK graph structure.

        Args:
            adjacency: Technique → list of possible next techniques.
            edge_weights: Optional (from_node, to_node) → transition probability.
        """
        # Compute prior probabilities from in-degree
        in_degree: dict[str, int] = {}
        for node, neighbors in adjacency.items():
            for neighbor in neighbors:
                in_degree[neighbor] = in_degree.get(neighbor, 0) + 1

        total_in = sum(in_degree.values()) or 1
        for node in set(list(adjacency.keys()) + list(in_degree.keys())):
            self._priors[node] = in_degree.get(node, 1) / total_in

        # Build CPTs: P(child | parent) = edge_weight / sum(all edges from parent)
        for parent, children in adjacency.items():
            total = len(children) if children else 1
            for child in children:
                weight = (edge_weights or {}).get(f"{parent}→{child}", 1.0)
                key = f"{parent}|{child}"
                self._cpts[key] = weight / total

        self._trained = True
        logger.info("Bayesian network initialized: %d nodes, %d CPTs",
                     len(self._priors), len(self._cpts))

    def joint_probability(self, path: list[str]) -> float:
        """Compute the joint probability of a complete attack path.

        P(path) = P(T0) × Π_i P(T_i | T_{i-1})

        Args:
            path: Ordered list of technique IDs.

        Returns:
            Joint probability (0-1), or 0.01 if no data.
        """
        if not path:
            return 0.0
        if not self._trained:
            return self._mock_probability(path)

        prob = self._priors.get(path[0], 0.01)
        for i in range(1, len(path)):
            key = f"{path[i-1]}|{path[i]}"
            transition = self._cpts.get(key, 0.01)
            prob *= transition

        return max(0.001, min(1.0, prob))

    def conditional_probability(self, observed: list[str], predicted: str) -> float:
        """Compute P(predicted | observed) — the probability of the next TTP.

        Uses the last observed TTP as the conditioning parent.
        """
        if not observed:
            return self._priors.get(predicted, 0.01)
        key = f"{observed[-1]}|{predicted}"
        return self._cpts.get(key, 0.01)

    def update_with_threat_intel(self, technique_id: str, prevalence: float) -> None:
        """Update a technique's prior with threat intelligence prevalence.

        Args:
            technique_id: ATT&CK technique ID.
            prevalence: 0-1 indicating current threat actor usage frequency.
        """
        if technique_id in self._priors:
            # Bayesian update: weighted average of prior and new evidence
            self._priors[technique_id] = 0.7 * self._priors[technique_id] + 0.3 * prevalence
            logger.debug("Updated prior for %s: %.4f", technique_id, self._priors[technique_id])

    def update_with_detection_coverage(self, technique_id: str, has_detection: bool) -> None:
        """Adjust probability based on whether the TTP has detection coverage.

        Techniques with detection coverage are more likely to be caught,
        so the prior is slightly reduced (we're more confident we'd catch it).
        """
        if technique_id in self._priors:
            factor = 0.9 if has_detection else 1.1
            self._priors[technique_id] = min(1.0, max(0.001, self._priors[technique_id] * factor))

    def _mock_probability(self, path: list[str]) -> float:
        """Mock probability estimate based on path length and diversity."""
        if len(path) <= 1:
            return 0.5
        # Exponential decay with path length
        return max(0.01, 0.8 ** len(path))
