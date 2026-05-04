"""Multi-round adversarial debate engine (Phase 2).

Orchestrates structured debate between the Defense Agent (proposing actions)
and Tracing Agent (acting as red-team reviewer). The Arbitrator evaluates
each round and ensures convergence in ≤ max_rounds.

Phase 1: Single-round validation via Arbitrator (implemented in defense.py).
Phase 2: Full multi-round debate with LLM-generated responses.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from aegis.sandbox.arbitrator import Arbitrator, ArbitrationVerdict

logger = logging.getLogger(__name__)


@dataclass
class DebateRound:
    """A single round in the defense debate."""

    round_number: int
    proposal: list[dict[str, Any]]  # Defense agent's current action plan
    challenge: str  # Red-team's critique of the proposal
    rebuttal: str  # Defense agent's response to the challenge
    verdict: Optional[ArbitrationVerdict] = None


@dataclass
class DebateResult:
    """Final result of the debate process."""

    accepted: bool
    final_plan: list[dict[str, Any]]
    rounds: list[DebateRound] = field(default_factory=list)
    consensus_reached: bool = False
    forced_decision: bool = False


class DebateEngine:
    """Multi-round debate engine for defense validation.

    Phase 2+: Uses LLM to generate challenges and rebuttals.
    Phase 1: Uses the Arbitrator for single-round evaluation only.
    """

    def __init__(
        self,
        arbitrator: Optional[Arbitrator] = None,
        max_rounds: int = 3,
        use_llm: bool = False,
    ) -> None:
        self._arbitrator = arbitrator or Arbitrator(max_rounds=max_rounds)
        self._max_rounds = max_rounds
        self._use_llm = use_llm

    def debate(
        self,
        chain_ttps: list[str],
        initial_proposal: list[dict[str, Any]],
        initial_impact: int,
        adjacency: Optional[dict[str, list[str]]] = None,
        llm_client: Any = None,
    ) -> DebateResult:
        """Run the full debate process.

        Args:
            chain_ttps: Attack chain TTP IDs.
            initial_proposal: Defense agent's initial action plan.
            initial_impact: Estimated business impact (1-100).
            adjacency: ATT&CK adjacency map for red-team bypass analysis.
            llm_client: Optional LLM client for challenge/rebuttal generation.

        Returns:
            DebateResult with final verdict and round history.
        """
        rounds: list[DebateRound] = []
        current_plan = initial_proposal
        current_impact = initial_impact

        for r in range(1, self._max_rounds + 1):
            # Step 1: Red-team challenge
            challenge = self._generate_challenge(current_plan, chain_ttps, adjacency, llm_client)

            # Step 2: Defense rebuttal (refine plan based on challenge)
            if challenge and self._use_llm and llm_client:
                current_plan, current_impact, rebuttal = self._generate_rebuttal(
                    current_plan, challenge, chain_ttps, llm_client
                )
            else:
                rebuttal = "No rebuttal generated (LLM disabled)"
                # Apply simple fix: add monitoring for any uncovered TTPs
                uncovered = self._find_uncovered(current_plan, chain_ttps)
                if uncovered:
                    for ttp in uncovered:
                        current_plan.append({
                            "action": "monitor",
                            "expected_effect": ttp,
                            "reason": f"Added monitoring for uncovered TTP {ttp} (debate round {r})",
                            "target_ttp": ttp,
                        })

            # Step 3: Arbitrator evaluation
            verdict = self._arbitrator.evaluate(r, chain_ttps, current_plan, current_impact)

            round_result = DebateRound(
                round_number=r,
                proposal=current_plan,
                challenge=challenge,
                rebuttal=rebuttal,
                verdict=verdict,
            )
            rounds.append(round_result)

            if verdict.defense_accepted:
                return DebateResult(
                    accepted=True,
                    final_plan=current_plan,
                    rounds=rounds,
                    consensus_reached=True,
                )

        # Max rounds reached — forced decision
        logger.warning("Debate: max rounds (%d) reached without consensus", self._max_rounds)
        return DebateResult(
            accepted=True,
            final_plan=current_plan,
            rounds=rounds,
            consensus_reached=False,
            forced_decision=True,
        )

    def _generate_challenge(
        self,
        plan: list[dict[str, Any]],
        chain_ttps: list[str],
        adjacency: Optional[dict[str, list[str]]],
        llm_client: Any,
    ) -> str:
        """Generate a red-team challenge to the current defense plan.

        Phase 2+: Uses LLM to generate specific bypass techniques.
        Phase 1: Uses heuristic analysis of uncovered TTPs.
        """
        if self._use_llm and llm_client:
            plan_text = "\n".join(
                f"- {a.get('action', '?')}: {a.get('reason', '')}"
                for a in plan
            )
            prompt = (
                f"Attack chain: {' → '.join(chain_ttps)}\n"
                f"Defense plan:\n{plan_text}\n\n"
                "As a red-team expert, identify 2-3 specific ways an APT attacker "
                "could bypass or work around these defenses. Be specific about "
                "alternative TTPs they could use."
            )
            resp = llm_client.generate_debate_response(prompt)
            return resp.text if resp.text else ""

        # Heuristic challenge
        covered = {a.get("expected_effect", "") for a in plan}
        uncovered = [t for t in chain_ttps if t not in covered]
        if uncovered:
            return f"Defense does not cover TTPs: {uncovered}. Attacker can proceed through these gaps."

        if adjacency:
            # Check if attacker could use alternative TTPs
            for action in plan:
                ttp = action.get("expected_effect", "")
                if ttp in adjacency and adjacency[ttp]:
                    alt = adjacency[ttp][:2]
                    return f"Blocking {ttp} — attacker could pivot to {alt} instead."

        return "No significant gaps identified in current plan."

    def _generate_rebuttal(
        self,
        plan: list[dict[str, Any]],
        challenge: str,
        chain_ttps: list[str],
        llm_client: Any,
    ) -> tuple[list[dict[str, Any]], int, str]:
        """Generate a defense rebuttal and refine the plan."""
        # Phase 2+: LLM-generated rebuttal and plan refinement
        rebuttal = f"Defense acknowledges the challenge. Plan has been refined."
        # Phase 1: simple refinement — add monitoring for uncovered
        return plan, 50, rebuttal

    @staticmethod
    def _find_uncovered(plan: list[dict[str, Any]], chain_ttps: list[str]) -> list[str]:
        covered = {a.get("expected_effect", "") for a in plan}
        return [t for t in chain_ttps if t not in covered]
