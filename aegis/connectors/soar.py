"""SOAR (Security Orchestration, Automation & Response) connector.

Provides an abstraction layer over SOAR platforms (Splunk Phantom, Palo Alto
XSOAR, Swimlane, etc.) so the Defense Agent can issue actions without knowing
platform-specific APIs.

MVP: Returns a structured action plan that a human operator can execute.
Phase 2+: Direct API integration with popular SOAR platforms.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class SOARPlatform(str, Enum):
    PHANTOM = "splunk_phantom"
    XSOAR = "palo_alto_xsoar"
    SWIMLANE = "swimlane"
    GENERIC = "generic"


class ActionStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class SOARAction:
    """A single action to be executed via SOAR."""

    action_id: str
    action_type: str  # block_ip, isolate_host, kill_process, etc.
    target: str  # IP, hostname, username, hash
    parameters: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    rollback_action: Optional[str] = None
    pre_check: Optional[str] = None
    status: ActionStatus = ActionStatus.PENDING
    error_message: str = ""


@dataclass
class SOARPlaybook:
    """A sequence of SOAR actions forming a defensive playbook."""

    playbook_id: str
    decision_id: str
    actions: list[SOARAction] = field(default_factory=list)
    business_impact_score: int = 0
    requires_approval: bool = True
    approved_by: Optional[str] = None


class SOARConnector:
    """Abstract SOAR platform connector.

    In Phase 1 (MVP), actions are recorded as structured JSON for manual
    execution. In Phase 2+, this connects to real SOAR APIs.
    """

    def __init__(self, platform: SOARPlatform = SOARPlatform.GENERIC, dry_run: bool = True) -> None:
        self._platform = platform
        self._dry_run = dry_run
        self._action_log: list[SOARAction] = []

    def build_playbook(self, decision_id: str, steps: list[dict[str, Any]], impact_score: int) -> SOARPlaybook:
        """Build a SOARPlaybook from DecisionScript steps.

        Args:
            decision_id: The DecisionScript ID.
            steps: List of dicts with {action, target, reason, rollback, pre_check}.
            impact_score: Business impact score (1-100).

        Returns:
            SOARPlaybook ready for execution or approval.
        """
        import uuid
        actions: list[SOARAction] = []
        for i, step in enumerate(steps):
            action = SOARAction(
                action_id=f"soar-{uuid.uuid4().hex[:8]}",
                action_type=step.get("action", "monitor"),
                target=str(step.get("target", "unknown")),
                parameters=step.get("parameters", {}),
                reason=step.get("reason", ""),
                rollback_action=step.get("rollback"),
                pre_check=step.get("pre_check"),
            )
            actions.append(action)

        playbook = SOARPlaybook(
            playbook_id=f"pb-{decision_id}",
            decision_id=decision_id,
            actions=actions,
            business_impact_score=impact_score,
            requires_approval=True,
        )
        logger.info("Built playbook %s with %d actions", playbook.playbook_id, len(actions))
        return playbook

    def execute_action(self, action: SOARAction) -> ActionStatus:
        """Execute a single SOAR action.

        MVP: Logs the action and returns PENDING (human must execute).
        Phase 2+: Calls SOAR API to execute.
        """
        if self._dry_run:
            logger.info("[DRY RUN] Would execute: %s on %s — %s", action.action_type, action.target, action.reason)
            action.status = ActionStatus.PENDING
            self._action_log.append(action)
            return ActionStatus.PENDING

        # Phase 2+: Real SOAR API call
        logger.warning("Real SOAR execution not yet implemented; action pending: %s", action.action_id)
        action.status = ActionStatus.PENDING
        self._action_log.append(action)
        return ActionStatus.PENDING

    def execute_playbook(self, playbook: SOARPlaybook) -> dict[str, ActionStatus]:
        """Execute all actions in a playbook sequentially.

        Stops on first failure and attempts rollback.
        """
        results: dict[str, ActionStatus] = {}
        executed: list[SOARAction] = []

        for action in playbook.actions:
            status = self.execute_action(action)
            results[action.action_id] = status
            executed.append(action)

            if status == ActionStatus.FAILED:
                logger.error("Action %s failed — rolling back", action.action_id)
                self._rollback(executed)
                break

        return results

    def _rollback(self, actions: list[SOARAction]) -> None:
        """Rollback executed actions in reverse order."""
        for action in reversed(actions):
            if action.rollback_action:
                logger.info("Rolling back: %s for %s", action.rollback_action, action.action_id)
                action.status = ActionStatus.ROLLED_BACK

    def get_action_log(self) -> list[SOARAction]:
        return list(self._action_log)

    def export_for_manual(self, playbook: SOARPlaybook) -> str:
        """Export a playbook as human-readable instructions with executable commands."""
        lines = [
            f"=== SOAR PLAYBOOK: {playbook.playbook_id} ===",
            f"Decision: {playbook.decision_id}",
            f"Business Impact: {playbook.business_impact_score}/100",
            f"Approval Required: {playbook.requires_approval}",
            f"Actions: {len(playbook.actions)}",
            "",
        ]
        for i, action in enumerate(playbook.actions, 1):
            lines.append(f"{i}. {action.action_type.upper()} → {action.target}")
            lines.append(f"   Reason: {action.reason}")
            if action.pre_check:
                lines.append(f"   Pre-check: {action.pre_check}")
            if action.rollback_action:
                lines.append(f"   Rollback: {action.rollback_action}")

            # Generate executable command based on action type
            cmd = self._action_to_command(action)
            if cmd:
                lines.append(f"   Command: {cmd}")
            lines.append("")
        return "\n".join(lines)

    def _action_to_command(self, action: SOARAction) -> str:
        """Convert an action to a platform-appropriate command string.

        These are example commands for common security tools.
        In production, these would be SOAR platform API calls.
        """
        commands = {
            "block_ip": f"iptables -A INPUT -s {action.target} -j DROP  # or: firewall add rule block-ip {action.target}",
            "block_domain": f"echo '127.0.0.1 {action.target}' >> /etc/hosts  # or: dns add blocklist {action.target}",
            "block_port": f"iptables -A INPUT -p tcp --dport {action.target} -j DROP",
            "isolate_host": f"soar isolate-endpoint --host {action.target} --reason \"{action.reason[:60]}\"",
            "kill_process": f"soar kill-process --host {action.target.split(':')[0] if ':' in action.target else 'unknown'} --pid {action.target}",
            "disable_account": f"soar disable-account --username {action.target} --reason \"{action.reason[:60]}\"",
            "reset_credential": f"soar reset-password --username {action.target} --force-mfa",
            "quarantine_file": f"soar quarantine-file --hash {action.target} --reason \"{action.reason[:60]}\"",
            "deploy_honeypot": f"soar deploy-honeypot --template c2-decoy --target-subnet {action.target}",
            "enable_mfa": f"soar enforce-mfa --username {action.target}",
            "segment_network": f"soar update-network-policy --isolate {action.target} --reason \"{action.reason[:60]}\"",
            "monitor": f"soar create-watchlist --target {action.target} --alert-on-match --reason \"{action.reason[:60]}\"",
        }
        return commands.get(action.action_type, f"soar execute --action {action.action_type} --target {action.target}")

    def export_as_json(self, playbook: SOARPlaybook) -> dict[str, Any]:
        """Export a playbook as a JSON dict for API consumption."""
        return {
            "playbook_id": playbook.playbook_id,
            "decision_id": playbook.decision_id,
            "business_impact_score": playbook.business_impact_score,
            "requires_approval": playbook.requires_approval,
            "actions": [
                {
                    "order": i + 1,
                    "action": a.action_type,
                    "target": a.target,
                    "reason": a.reason,
                    "command": self._action_to_command(a),
                    "pre_check": a.pre_check,
                    "rollback": a.rollback_action,
                }
                for i, a in enumerate(playbook.actions)
            ],
        }
