"""Monte Carlo Tree Search for defensive action game-tree simulation (Phase 2).

Simulates multi-step attacker-defender interactions to find optimal
defensive strategies that minimize residual risk while preserving
business continuity.

Dependencies (Phase 2): numpy (for tree search), red_team (attacker model)
"""

from __future__ import annotations

import logging
import math
import random
from dataclasses import dataclass, field
from typing import Any, Optional

from aegis.sandbox.red_team import RedTeamSimulator, MODERATE_ATTACKER, APT_ATTACKER

logger = logging.getLogger(__name__)


@dataclass
class MCTSNode:
    """A node in the MCTS game tree."""

    state_id: str = ""
    visits: int = 0
    total_value: float = 0.0  # Cumulative reward
    children: dict[str, MCTSNode] = field(default_factory=dict)
    parent: Optional[MCTSNode] = None
    action: str = ""  # The defensive action taken to reach this node
    is_terminal: bool = False

    @property
    def avg_value(self) -> float:
        if self.visits == 0:
            return 0.0
        return self.total_value / self.visits

    def ucb1(self, parent_visits: int, exploration: float = 1.414) -> float:
        """Upper Confidence Bound for Trees selection."""
        if self.visits == 0:
            return float("inf")
        return self.avg_value + exploration * math.sqrt(math.log(parent_visits) / self.visits)


class MCTSDefenseSimulator:
    """MCTS-based defense strategy simulation.

    Phase 2+: Full game-tree search with red-team adversary model.
    Phase 1: Stub that returns the initial defense proposal unchanged.
    """

    def __init__(
        self,
        max_iterations: int = 100,
        max_depth: int = 5,
        exploration_constant: float = 1.414,
        seed: int = 42,
    ) -> None:
        self._max_iterations = max_iterations
        self._max_depth = max_depth
        self._exploration = exploration_constant
        self._rng = random.Random(seed)
        self._red_team = RedTeamSimulator(seed=seed)
        self._root: Optional[MCTSNode] = None

    def search(
        self,
        attack_chain: list[str],
        defense_options: list[dict[str, Any]],
        simulations_per_node: int = 10,
    ) -> tuple[list[dict[str, Any]], float]:
        """Run MCTS to find the optimal defense strategy.

        Args:
            attack_chain: Ordered list of TTP IDs in the attack chain.
            defense_options: Candidate defensive actions per TTP.
            simulations_per_node: Rollouts per MCTS iteration.

        Returns:
            (optimized_defense_plan, expected_block_rate)
        """
        logger.warning("MCTS search not yet fully implemented (Phase 2+)")

        # Phase 1 fallback: run worst-case red-team analysis and return
        blocked_ttps = [d.get("expected_effect", "") for d in defense_options]
        worst = self._red_team.run_worst_case([b for b in blocked_ttps if b])

        # Compute a simple block rate
        covered = set(blocked_ttps) & set(attack_chain)
        block_rate = len(covered) / max(len(attack_chain), 1)

        logger.info("MCTS (Phase 1 fallback): block_rate=%.2f", block_rate)
        return defense_options, block_rate

    def _select(self, node: MCTSNode) -> MCTSNode:
        """Select the most promising child node using UCB1."""
        while node.children and not node.is_terminal:
            best_child = max(node.children.values(), key=lambda c: c.ucb1(node.visits, self._exploration))
            node = best_child
        return node

    def _expand(self, node: MCTSNode, available_actions: list[str]) -> Optional[MCTSNode]:
        """Expand the tree by adding a new child node."""
        if not available_actions or node.is_terminal:
            return None

        for action in available_actions:
            if action not in node.children:
                child = MCTSNode(
                    state_id=f"{node.state_id}_{action}",
                    parent=node,
                    action=action,
                )
                node.children[action] = child
                return child
        return None

    def _simulate(self, node: MCTSNode, max_depth: int = 5) -> float:
        """Simulate a random rollout from this node."""
        # Phase 2+: Run red-team simulation to get rollout reward
        # For now, random reward
        return self._rng.random()

    def _backpropagate(self, node: MCTSNode, reward: float) -> None:
        """Backpropagate the reward up the tree."""
        while node is not None:
            node.visits += 1
            node.total_value += reward
            node = node.parent


def optimize_defense(
    attack_chain: list[str],
    defense_actions: list[dict[str, Any]],
    use_mcts: bool = False,
) -> tuple[list[dict[str, Any]], float]:
    """Convenience function to optimize a defense plan.

    Args:
        attack_chain: Attack chain TTP IDs.
        defense_actions: Proposed defensive actions.
        use_mcts: Whether to use MCTS (Phase 2+) or heuristic (Phase 1).

    Returns:
        (optimized_actions, expected_block_rate)
    """
    if not use_mcts:
        # Phase 1 heuristic
        covered = sum(1 for d in defense_actions if d.get("expected_effect", "") in attack_chain)
        rate = covered / max(len(attack_chain), 1)
        return defense_actions, rate

    sim = MCTSDefenseSimulator(max_iterations=50)
    return sim.search(attack_chain, defense_actions)
