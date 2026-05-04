"""Debate arbitrator for Defense-Tracing multi-round adversarial verification.

Solves: LLM-based debate between Defense and Tracing agents may not converge.
The Arbitrator provides a third-party evaluation based on quantitative metrics:
block rate, business impact, human cost, and coverage completeness.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ArbitrationVerdict:
    """The result of an arbitration round."""

    round_number: int
    defense_accepted: bool  # True if defense's proposal is deemed sufficient
    reason: str
    blocking_rate: float = 0.0  # Fraction of chain TTPs addressed
    business_impact_score: int = 0
    uncovered_ttps: list[str] = field(default_factory=list)
    required_changes: list[str] = field(default_factory=list)

    # Quantitative metrics for the verdict
    coverage_score: float = 0.0  # 0-1: how well the chain is covered
    residual_risk: float = 0.0  # 0-1: risk remaining after defense


class Arbitrator:
    """Third-party arbitrator for agent debate convergence.

    Evaluates defense proposals against attack chains using objective metrics,
    not LLM opinion. This guarantees convergence: after each round, the
    arbitrator provides a concrete score and actionable feedback.
    """

    def __init__(
        self,
        max_rounds: int = 3,
        coverage_threshold: float = 0.8,
        impact_threshold: int = 70,
    ) -> None:
        """
        Args:
            max_rounds: Maximum debate rounds before forced decision.
            coverage_threshold: Minimum TTP coverage to accept a defense (0-1).
            impact_threshold: Maximum acceptable business impact score (1-100).
        """
        self._max_rounds = max_rounds
        self._coverage_threshold = coverage_threshold
        self._impact_threshold = impact_threshold
        self._round_log: list[ArbitrationVerdict] = []

    def evaluate(
        self,
        round_num: int,
        chain_ttps: list[str],
        defense_actions: list[dict[str, Any]],
        business_impact_score: int,
    ) -> ArbitrationVerdict:
        """Evaluate a defense proposal against an attack chain.

        Args:
            round_num: Current debate round (1-based).
            chain_ttps: List of TTP IDs from the attack chain.
            defense_actions: Defense agent's proposed actions, each dict with
                           at minimum {"action": str, "expected_effect": str,
                           "target_ttp": str}.
            business_impact_score: Estimated business impact (1-100).

        Returns:
            ArbitrationVerdict with acceptance decision and feedback.
        """
        # Extract which TTPs are covered by which actions
        covered_ttps: set[str] = set()
        for action in defense_actions:
            ttp = action.get("target_ttp", "") or action.get("expected_effect", "")
            # Also check if any action maps to a TTP via mitigation mapping
            for tid in chain_ttps:
                if tid in action.get("expected_effect", "") or tid in action.get("reason", ""):
                    covered_ttps.add(tid)

        uncovered = [t for t in chain_ttps if t not in covered_ttps]
        coverage = len(covered_ttps) / max(len(chain_ttps), 1)
        blocking_rate = len(defense_actions) / max(len(chain_ttps), 1)

        # Residual risk: uncovered TTPs weighted by their position in the chain
        # (later-stage TTPs = higher residual risk)
        residual_risk = 0.0
        for i, ttp in enumerate(chain_ttps):
            if ttp not in covered_ttps:
                residual_risk += (i + 1) / len(chain_ttps)  # Weighted by position
        residual_risk = min(1.0, residual_risk / max(len(uncovered), 1)) if uncovered else 0.0

        # Decision logic
        if coverage >= self._coverage_threshold and business_impact_score <= self._impact_threshold:
            accepted = True
            reason = (
                f"Coverage {coverage:.0%} meets threshold {self._coverage_threshold:.0%}, "
                f"impact {business_impact_score} ≤ {self._impact_threshold}"
            )
            changes = []
        elif round_num >= self._max_rounds:
            accepted = True  # Forced acceptance at max rounds
            reason = f"Max rounds ({self._max_rounds}) reached — forced decision. Coverage: {coverage:.0%}"
            changes = [f"Address uncovered TTPs: {uncovered}"]
        else:
            accepted = False
            reason = (
                f"Insufficient: coverage {coverage:.0%} < {self._coverage_threshold:.0%} "
                f"or impact {business_impact_score} > {self._impact_threshold}"
            )
            changes = [
                f"Address uncovered TTPs: {uncovered}",
                f"Reduce business impact from {business_impact_score} to ≤ {self._impact_threshold}",
            ] if uncovered else [
                f"Reduce business impact from {business_impact_score} to ≤ {self._impact_threshold}",
            ]

        verdict = ArbitrationVerdict(
            round_number=round_num,
            defense_accepted=accepted,
            reason=reason,
            blocking_rate=blocking_rate,
            business_impact_score=business_impact_score,
            uncovered_ttps=uncovered,
            required_changes=changes,
            coverage_score=coverage,
            residual_risk=residual_risk,
        )

        self._round_log.append(verdict)
        logger.info(
            "Arbitration round %d: accepted=%s coverage=%.2f impact=%d risk=%.2f",
            round_num, accepted, coverage, business_impact_score, residual_risk,
        )

        return verdict

    def get_round_log(self) -> list[ArbitrationVerdict]:
        return list(self._round_log)

    def reset(self) -> None:
        self._round_log.clear()


def run_debate_arbitration(
    chain_ttps: list[str],
    initial_defense: list[dict[str, Any]],
    initial_impact: int,
    max_rounds: int = 3,
) -> tuple[bool, list[dict[str, Any]], list[ArbitrationVerdict]]:
    """Run a full debate arbitration cycle.

    This is the reference implementation for Phase 2+ multi-round debate.
    In the MVP, it simply evaluates the initial proposal and returns.

    Args:
        chain_ttps: Attack chain TTP IDs.
        initial_defense: Defense agent's proposed actions.
        initial_impact: Estimated business impact.
        max_rounds: Maximum debate rounds.

    Returns:
        (accepted, final_actions, verdict_log)
    """
    arb = Arbitrator(max_rounds=max_rounds)
    current_defense = initial_defense
    current_impact = initial_impact

    for round_num in range(1, max_rounds + 1):
        verdict = arb.evaluate(round_num, chain_ttps, current_defense, current_impact)

        if verdict.defense_accepted:
            return True, current_defense, arb.get_round_log()

        # In Phase 2+, this is where the Defense Agent would refine based on
        # verdict.required_changes and re-submit. For MVP, break after first round.
        if round_num >= max_rounds:
            return False, current_defense, arb.get_round_log()

    return False, current_defense, arb.get_round_log()
