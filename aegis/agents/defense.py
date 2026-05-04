"""Defense Agent — generates adaptive defense strategies from attack chains.

Improvements over original design:
- Quantified business impact: criticality × downtime × user_count
- Independent red-team strategy: attacker simulation NOT derived from Tracing Agent
- Debate arbitration: third-party evaluator ensures convergence in ≤3 rounds
- Rollback: every defensive action includes rollback plan
- Pre-check: every action includes condition to verify before execution

Phase 1 (MVP): Rule-based mitigation mapping — TTP → SOAR action.
Phase 2+: MCTS game-tree search, multi-round debate with Tracing Agent.

Input:  AttackChain (from threat.chain)
Output: DecisionScript published to threat.decision
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from aegis.agents.base import BaseAgent
from aegis.core.models import (
    AgentRole,
    AttackChain,
    BusinessImpact,
    DecisionAction,
    DecisionScript,
    DecisionStep,
    Entity,
)
from aegis.sandbox.red_team import RedTeamSimulator, MODERATE_ATTACKER, APT_ATTACKER
from aegis.sandbox.arbitrator import Arbitrator

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# TTP → Mitigation Mapping (extended with rollback and pre-check)
# ──────────────────────────────────────────────

TTP_TO_MITIGATION: dict[str, list[dict[str, Any]]] = {
    "T1566": [  # Phishing
        {"action": DecisionAction.DISABLE_ACCOUNT, "reason": "Disable compromised user account",
         "rollback": DecisionAction.ENABLE_MFA, "pre_check": "user_exists(username)",
         "impact_base": 15},
        {"action": DecisionAction.RESET_CREDENTIAL, "reason": "Force password reset for affected user",
         "rollback": None, "pre_check": "account_is_human(username)",
         "impact_base": 10},
        {"action": DecisionAction.BLOCK_DOMAIN, "reason": "Block phishing sender domain at email gateway",
         "rollback": None, "pre_check": "domain_not_whitelisted(domain)",
         "impact_base": 5},
    ],
    "T1189": [  # Drive-by Compromise
        {"action": DecisionAction.BLOCK_DOMAIN, "reason": "Block malicious domain at proxy",
         "rollback": None, "pre_check": "domain_not_internal(domain)",
         "impact_base": 5},
        {"action": DecisionAction.MONITOR, "reason": "Monitor for unexpected browser process spawns",
         "rollback": None, "pre_check": None,
         "impact_base": 2},
    ],
    "T1190": [  # Exploit Public-Facing App
        {"action": DecisionAction.ISOLATE_HOST, "reason": "Isolate compromised web server",
         "rollback": DecisionAction.SEGMENT_NETWORK, "pre_check": "host_is_dmz(hostname)",
         "impact_base": 60},
        {"action": DecisionAction.BLOCK_IP, "reason": "Block attacker source IP at WAF",
         "rollback": None, "pre_check": "ip_not_internal(source_ip)",
         "impact_base": 10},
        {"action": DecisionAction.SEGMENT_NETWORK, "reason": "Restrict DMZ → internal traffic",
         "rollback": None, "pre_check": "network_policy_exists(dmz, internal)",
         "impact_base": 30},
    ],
    "T1078": [  # Valid Accounts
        {"action": DecisionAction.DISABLE_ACCOUNT, "reason": "Disable compromised account",
         "rollback": DecisionAction.ENABLE_MFA, "pre_check": "user_exists(username)",
         "impact_base": 25},
        {"action": DecisionAction.RESET_CREDENTIAL, "reason": "Force credential reset",
         "rollback": None, "pre_check": "account_is_human(username)",
         "impact_base": 10},
        {"action": DecisionAction.ENABLE_MFA, "reason": "Enforce MFA for account",
         "rollback": None, "pre_check": "mfa_not_already_enabled(username)",
         "impact_base": 5},
    ],
    "T1133": [  # External Remote Services
        {"action": DecisionAction.BLOCK_IP, "reason": "Block source IP at firewall",
         "rollback": None, "pre_check": "ip_not_internal(source_ip)",
         "impact_base": 15},
        {"action": DecisionAction.BLOCK_PORT, "reason": "Close exposed RDP/VPN port",
         "rollback": None, "pre_check": "port_is_external_facing(port)",
         "impact_base": 20},
    ],
    "T1195": [  # Supply Chain Compromise
        {"action": DecisionAction.ISOLATE_HOST, "reason": "Isolate host with compromised software",
         "rollback": DecisionAction.MONITOR, "pre_check": "host_is_not_dc(hostname)",
         "impact_base": 55},
        {"action": DecisionAction.QUARANTINE_FILE, "reason": "Quarantine compromised software binary",
         "rollback": None, "pre_check": "file_hash_known(malware_hash)",
         "impact_base": 10},
    ],
    "T1059": [  # Command & Scripting Interpreter
        {"action": DecisionAction.KILL_PROCESS, "reason": "Kill suspicious PowerShell/cmd processes",
         "rollback": None, "pre_check": "process_not_system_critical(pid)",
         "impact_base": 15},
        {"action": DecisionAction.MONITOR, "reason": "Enable script block logging for future detection",
         "rollback": None, "pre_check": None,
         "impact_base": 2},
    ],
    "T1203": [  # Exploitation for Client Execution
        {"action": DecisionAction.ISOLATE_HOST, "reason": "Isolate affected endpoint",
         "rollback": DecisionAction.MONITOR, "pre_check": "host_is_workstation(hostname)",
         "impact_base": 40},
        {"action": DecisionAction.BLOCK_DOMAIN, "reason": "Block exploit kit domain",
         "rollback": None, "pre_check": "domain_not_whitelisted(domain)",
         "impact_base": 5},
    ],
    "T1204": [  # User Execution (malicious file)
        {"action": DecisionAction.QUARANTINE_FILE, "reason": "Quarantine malicious file by hash",
         "rollback": None, "pre_check": "file_hash_not_false_positive(malware_hash)",
         "impact_base": 10},
        {"action": DecisionAction.KILL_PROCESS, "reason": "Kill associated processes",
         "rollback": None, "pre_check": "process_not_system_critical(pid)",
         "impact_base": 10},
    ],
    "T1210": [  # Remote Services Exploit
        {"action": DecisionAction.ISOLATE_HOST, "reason": "Isolate exploited host",
         "rollback": DecisionAction.MONITOR, "pre_check": "host_is_not_dc(hostname)",
         "impact_base": 55},
        {"action": DecisionAction.BLOCK_PORT, "reason": "Block exploited service port",
         "rollback": None, "pre_check": "port_is_not_essential(port)",
         "impact_base": 20},
    ],
    "T1547": [  # Boot/Logon Autostart
        {"action": DecisionAction.QUARANTINE_FILE, "reason": "Remove persistence mechanism from startup",
         "rollback": None, "pre_check": "registry_key_exists(key_path)",
         "impact_base": 10},
        {"action": DecisionAction.MONITOR, "reason": "Alert on registry run key modifications",
         "rollback": None, "pre_check": None,
         "impact_base": 2},
    ],
    "T1053": [  # Scheduled Task
        {"action": DecisionAction.KILL_PROCESS, "reason": "Kill scheduled task process",
         "rollback": None, "pre_check": "process_is_scheduled_task(pid)",
         "impact_base": 10},
        {"action": DecisionAction.QUARANTINE_FILE, "reason": "Remove malicious scheduled task",
         "rollback": None, "pre_check": "scheduled_task_exists(task_name)",
         "impact_base": 5},
    ],
    "T1505": [  # Server Software Component
        {"action": DecisionAction.ISOLATE_HOST, "reason": "Isolate compromised server",
         "rollback": DecisionAction.MONITOR, "pre_check": "host_is_not_single_point_of_failure(hostname)",
         "impact_base": 60},
        {"action": DecisionAction.KILL_PROCESS, "reason": "Terminate web shell process",
         "rollback": None, "pre_check": "process_is_web_server_child(pid)",
         "impact_base": 15},
    ],
    "T1068": [  # Exploitation for Priv Escalation
        {"action": DecisionAction.ISOLATE_HOST, "reason": "Isolate host to prevent lateral spread",
         "rollback": DecisionAction.MONITOR, "pre_check": "host_can_be_isolated(hostname)",
         "impact_base": 45},
        {"action": DecisionAction.KILL_PROCESS, "reason": "Kill elevated process",
         "rollback": None, "pre_check": "process_is_elevated(pid)",
         "impact_base": 15},
    ],
    "T1562": [  # Impair Defenses
        {"action": DecisionAction.MONITOR, "reason": "Alert if security tool processes stop",
         "rollback": None, "pre_check": None,
         "impact_base": 2},
        {"action": DecisionAction.ISOLATE_HOST, "reason": "Isolate host with disabled defenses",
         "rollback": DecisionAction.MONITOR, "pre_check": "host_can_be_isolated(hostname)",
         "impact_base": 40},
    ],
    "T1070": [  # Indicator Removal
        {"action": DecisionAction.MONITOR, "reason": "Alert on log clearing and timestamp manipulation",
         "rollback": None, "pre_check": None,
         "impact_base": 2},
        {"action": DecisionAction.ISOLATE_HOST, "reason": "Isolate host attempting log tampering",
         "rollback": DecisionAction.MONITOR, "pre_check": "host_can_be_isolated(hostname)",
         "impact_base": 40},
    ],
    "T1027": [  # Obfuscated Files
        {"action": DecisionAction.QUARANTINE_FILE, "reason": "Quarantine obfuscated files",
         "rollback": None, "pre_check": "file_hash_not_false_positive(malware_hash)",
         "impact_base": 10},
        {"action": DecisionAction.MONITOR, "reason": "Enable AMSI/deep script inspection",
         "rollback": None, "pre_check": None,
         "impact_base": 2},
    ],
    "T1003": [  # OS Credential Dumping
        {"action": DecisionAction.ISOLATE_HOST, "reason": "Isolate host running credential dump",
         "rollback": DecisionAction.MONITOR, "pre_check": "host_can_be_isolated(hostname)",
         "impact_base": 50},
        {"action": DecisionAction.KILL_PROCESS, "reason": "Kill mimikatz/lsass access process",
         "rollback": None, "pre_check": "process_accessing_lsass(pid)",
         "impact_base": 15},
        {"action": DecisionAction.RESET_CREDENTIAL, "reason": "Force password reset for all users on affected host",
         "rollback": None, "pre_check": "affected_users_under_threshold(hostname, 50)",
         "impact_base": 25},
    ],
    "T1110": [  # Brute Force
        {"action": DecisionAction.BLOCK_IP, "reason": "Block brute-force source IP",
         "rollback": None, "pre_check": "ip_not_internal(source_ip)",
         "impact_base": 20},
        {"action": DecisionAction.DISABLE_ACCOUNT, "reason": "Temporarily lock targeted account",
         "rollback": DecisionAction.ENABLE_MFA, "pre_check": "user_exists(username)",
         "impact_base": 15},
        {"action": DecisionAction.ENABLE_MFA, "reason": "Enforce MFA for targeted account",
         "rollback": None, "pre_check": "mfa_not_already_enabled(username)",
         "impact_base": 5},
    ],
    "T1083": [  # File & Directory Discovery
        {"action": DecisionAction.MONITOR, "reason": "Alert on mass file enumeration patterns",
         "rollback": None, "pre_check": None,
         "impact_base": 2},
        {"action": DecisionAction.ISOLATE_HOST, "reason": "Isolate if combined with other indicators",
         "rollback": DecisionAction.MONITOR, "pre_check": "host_can_be_isolated(hostname) AND multiple_ttp_observed",
         "impact_base": 30},
    ],
    "T1046": [  # Network Service Scanning
        {"action": DecisionAction.BLOCK_IP, "reason": "Block scanning source IP",
         "rollback": None, "pre_check": "ip_not_internal(source_ip)",
         "impact_base": 20},
        {"action": DecisionAction.SEGMENT_NETWORK, "reason": "Restrict lateral network access from scanning host",
         "rollback": None, "pre_check": "network_segment_isolatable(hostname)",
         "impact_base": 35},
    ],
    "T1021": [  # Lateral Movement via Remote Services
        {"action": DecisionAction.ISOLATE_HOST, "reason": "Isolate source AND destination hosts",
         "rollback": DecisionAction.MONITOR, "pre_check": "both_hosts_isolatable(src_host, dst_host)",
         "impact_base": 65},
        {"action": DecisionAction.BLOCK_PORT, "reason": "Block SMB/RPC/WMI ports between segments",
         "rollback": None, "pre_check": "port_is_lateral_movement_channel(port)",
         "impact_base": 25},
        {"action": DecisionAction.DISABLE_ACCOUNT, "reason": "Disable account used for lateral movement",
         "rollback": DecisionAction.ENABLE_MFA, "pre_check": "user_exists(username) AND user_not_domain_admin(username)",
         "impact_base": 25},
    ],
    "T1570": [  # Lateral Tool Transfer
        {"action": DecisionAction.QUARANTINE_FILE, "reason": "Quarantine transferred tool on destination",
         "rollback": None, "pre_check": "file_hash_not_false_positive(malware_hash)",
         "impact_base": 10},
        {"action": DecisionAction.ISOLATE_HOST, "reason": "Isolate destination host",
         "rollback": DecisionAction.MONITOR, "pre_check": "host_can_be_isolated(hostname)",
         "impact_base": 40},
    ],
    "T1560": [  # Archive Collected Data
        {"action": DecisionAction.ISOLATE_HOST, "reason": "Isolate host archiving data",
         "rollback": DecisionAction.MONITOR, "pre_check": "host_can_be_isolated(hostname)",
         "impact_base": 40},
        {"action": DecisionAction.BLOCK_PORT, "reason": "Block outbound FTP/SCP/rsync from host",
         "rollback": None, "pre_check": "port_is_file_transfer(port)",
         "impact_base": 10},
    ],
    "T1071": [  # Application Layer Protocol (C2)
        {"action": DecisionAction.BLOCK_IP, "reason": "Block C2 IP address",
         "rollback": None, "pre_check": "ip_not_internal(ip) AND ip_not_cdn(ip)",
         "impact_base": 20},
        {"action": DecisionAction.BLOCK_DOMAIN, "reason": "Block C2 domain at DNS/proxy",
         "rollback": None, "pre_check": "domain_not_internal(domain) AND domain_not_critical_service(domain)",
         "impact_base": 15},
        {"action": DecisionAction.DEPLOY_HONEYPOT, "reason": "Deploy decoy to monitor C2 activity",
         "rollback": None, "pre_check": "honeypot_capacity_available()",
         "impact_base": 5},
    ],
    "T1573": [  # Encrypted Channel
        {"action": DecisionAction.MONITOR, "reason": "Inspect encrypted traffic anomalies (TLS fingerprinting)",
         "rollback": None, "pre_check": "tls_inspection_capable()",
         "impact_base": 3},
        {"action": DecisionAction.BLOCK_DOMAIN, "reason": "Block anomalous encrypted channel destination",
         "rollback": None, "pre_check": "domain_not_whitelisted(domain)",
         "impact_base": 15},
    ],
    "T1105": [  # Ingress Tool Transfer
        {"action": DecisionAction.QUARANTINE_FILE, "reason": "Quarantine downloaded tool by hash",
         "rollback": None, "pre_check": "file_hash_not_false_positive(malware_hash)",
         "impact_base": 10},
        {"action": DecisionAction.BLOCK_DOMAIN, "reason": "Block tool download source domain",
         "rollback": None, "pre_check": "domain_not_internal(domain)",
         "impact_base": 5},
    ],
    "T1048": [  # Exfiltration Over Alternative Protocol
        {"action": DecisionAction.ISOLATE_HOST, "reason": "Isolate host performing data exfil",
         "rollback": DecisionAction.MONITOR, "pre_check": "host_can_be_isolated(hostname)",
         "impact_base": 55},
        {"action": DecisionAction.BLOCK_IP, "reason": "Block exfil destination IP",
         "rollback": None, "pre_check": "ip_not_internal(ip)",
         "impact_base": 20},
        {"action": DecisionAction.BLOCK_PORT, "reason": "Block non-standard outbound port",
         "rollback": None, "pre_check": "port_is_non_standard_outbound(port)",
         "impact_base": 10},
    ],
    "T1567": [  # Exfiltration Over Web Service
        {"action": DecisionAction.BLOCK_DOMAIN, "reason": "Block exfil web service domain",
         "rollback": None, "pre_check": "domain_is_known_exfil_service(domain)",
         "impact_base": 5},
        {"action": DecisionAction.ISOLATE_HOST, "reason": "Isolate exfiltrating host",
         "rollback": DecisionAction.MONITOR, "pre_check": "host_can_be_isolated(hostname)",
         "impact_base": 45},
    ],
    "T1485": [  # Data Destruction
        {"action": DecisionAction.ISOLATE_HOST, "reason": "Isolate host immediately (emergency)",
         "rollback": None, "pre_check": None,
         "impact_base": 80},
        {"action": DecisionAction.KILL_PROCESS, "reason": "Kill destructive processes",
         "rollback": None, "pre_check": None,
         "impact_base": 20},
    ],
    "T1486": [  # Data Encrypted for Impact (Ransomware)
        {"action": DecisionAction.ISOLATE_HOST, "reason": "Isolate ransomware host immediately (emergency)",
         "rollback": None, "pre_check": None,
         "impact_base": 80},
        {"action": DecisionAction.KILL_PROCESS, "reason": "Kill encryption process",
         "rollback": None, "pre_check": None,
         "impact_base": 20},
        {"action": DecisionAction.BLOCK_IP, "reason": "Block ransomware C2 IP",
         "rollback": None, "pre_check": None,
         "impact_base": 20},
    ],
}

# Impact weight per asset criticality (1-5)
CRITICALITY_IMPACT_MULTIPLIER: dict[int, float] = {
    1: 0.3, 2: 0.6, 3: 1.0, 4: 1.5, 5: 2.0,
}


class DefenseAgent(BaseAgent):
    """Adaptive Defense Agent - generates DecisionScripts from AttackChains."""

    @property
    def agent_role(self) -> AgentRole:
        return AgentRole.DEFENSE

    def __init__(
        self,
        agent_id: str = "",
        max_debate_rounds: int = 3,
        enable_mcts: bool = False,
        enable_debate: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_id=agent_id, **kwargs)
        self.max_debate_rounds = max_debate_rounds
        self.enable_mcts = enable_mcts
        self.enable_debate = enable_debate
        self._red_team = RedTeamSimulator()
        self._arbitrator = Arbitrator(max_rounds=max_debate_rounds)

    def on_chain(self, chain: AttackChain, correlation_id: Optional[str]) -> None:
        logger.info("Processing chain %s (%d steps)", chain.chain_id, chain.step_count)
        decision = self.generate_decision(chain)
        if decision:
            if self.enable_debate:
                self._initiate_debate(decision, chain, correlation_id)
            else:
                self.publish_decision(decision, correlation_id or chain.chain_id)
                logger.info("Published decision %s", decision.decision_id)

    def generate_decision(self, chain: AttackChain) -> Optional[DecisionScript]:
        if not chain.nodes:
            return None
        candidate_actions: list[dict[str, Any]] = []
        for node in chain.nodes:
            tid = node.technique_id
            if node.is_predicted:
                candidate_actions.append({"action": DecisionAction.MONITOR, "reason": f"Monitor for predicted {tid}", "target_ttp": tid, "rollback": None, "pre_check": None, "impact_base": 2})
                continue
            for m in TTP_TO_MITIGATION.get(tid, []):
                candidate_actions.append({**m, "target_ttp": tid})
        if not candidate_actions:
            return DecisionScript(chain_id=chain.chain_id, consensus_reached=False, requires_human_approval=True)
        ordered_steps = self._prioritize_actions(candidate_actions, chain)
        impact = self._assess_business_impact_quantified(ordered_steps, chain)
        decision = DecisionScript(chain_id=chain.chain_id, steps=ordered_steps, business_impact=impact, consensus_reached=not self.enable_debate, requires_human_approval=True)
        if self.enable_mcts:
            decision = self._mcts_validate(decision, chain)
        return decision

    def _prioritize_actions(self, candidate_actions: list[dict[str, Any]], chain: AttackChain) -> list[DecisionStep]:
        seen_actions: set[tuple[DecisionAction, str]] = set()
        ordered_steps: list[DecisionStep] = []
        action_priority = [DecisionAction.ISOLATE_HOST, DecisionAction.DISABLE_ACCOUNT, DecisionAction.KILL_PROCESS, DecisionAction.BLOCK_IP, DecisionAction.BLOCK_DOMAIN, DecisionAction.BLOCK_PORT, DecisionAction.SEGMENT_NETWORK, DecisionAction.QUARANTINE_FILE, DecisionAction.RESET_CREDENTIAL, DecisionAction.DEPLOY_HONEYPOT, DecisionAction.ENABLE_MFA, DecisionAction.MONITOR]
        for priority_action in action_priority:
            for ca in candidate_actions:
                action = ca["action"]
                target_ttp = ca.get("target_ttp", "")
                key = (action, target_ttp)
                if action == priority_action and key not in seen_actions:
                    seen_actions.add(key)
                    target = self._infer_target(action, chain)
                    ordered_steps.append(DecisionStep(order=len(ordered_steps)+1, action=action, target=target, reason=f"{ca['reason']} (TTP: {target_ttp})", expected_effect=f"Blocks or detects {target_ttp}", rollback_action=ca.get("rollback"), pre_check=ca.get("pre_check")))
        return ordered_steps

    def _infer_target(self, action: DecisionAction, chain: AttackChain) -> Entity:
        entities = chain.nodes[0].entities_involved if chain.nodes else []
        m = {DecisionAction.BLOCK_IP: "ip", DecisionAction.BLOCK_DOMAIN: "domain", DecisionAction.ISOLATE_HOST: "host", DecisionAction.DISABLE_ACCOUNT: "user", DecisionAction.KILL_PROCESS: "process", DecisionAction.QUARANTINE_FILE: "hash", DecisionAction.SEGMENT_NETWORK: "host"}
        etype = m.get(action, "host")
        match = next((e for e in entities if e.entity_type == etype), None)
        return match if match else Entity(entity_type=etype, value="unknown", metadata={"inferred": True})

    def _assess_business_impact_quantified(self, steps: list[DecisionStep], chain: AttackChain, asset_criticality: int = 3, user_count: int = 50) -> BusinessImpact:
        import math
        crit_mult = CRITICALITY_IMPACT_MULTIPLIER.get(asset_criticality, 1.0)
        user_mult = 1.0 + max(0, math.log2(max(user_count, 1)/10.0)) * 0.5
        impact_map = {DecisionAction.ISOLATE_HOST: 60, DecisionAction.DISABLE_ACCOUNT: 25, DecisionAction.KILL_PROCESS: 20, DecisionAction.BLOCK_IP: 20, DecisionAction.BLOCK_DOMAIN: 15, DecisionAction.BLOCK_PORT: 20, DecisionAction.SEGMENT_NETWORK: 40, DecisionAction.QUARANTINE_FILE: 10, DecisionAction.RESET_CREDENTIAL: 15, DecisionAction.DEPLOY_HONEYPOT: 5, DecisionAction.ENABLE_MFA: 5, DecisionAction.MONITOR: 2}
        raw = sum(impact_map.get(s.action, 10) * crit_mult * user_mult for s in steps)
        score = min(100, int(raw/max(len(steps), 1)) + min(25, len(steps)*3))
        entities = list({s.target.value for s in steps if s.target and s.target.value != "unknown"})
        users = sum(1 for s in steps if s.target.entity_type in ("user",))
        downtime = sum(15 if s.action == DecisionAction.ISOLATE_HOST else 5 if s.action in (DecisionAction.DISABLE_ACCOUNT, DecisionAction.SEGMENT_NETWORK) else 1 for s in steps)
        return BusinessImpact(score=score, affected_services=entities, affected_user_count=users, estimated_downtime_minutes=downtime, justification=f"Affects {len(entities)} entities (crit={asset_criticality}, users~{user_count})")

    def _mcts_validate(self, decision: DecisionScript, chain: AttackChain) -> DecisionScript:
        blocked = [s.expected_effect for s in decision.steps]
        worst = self._red_team.run_worst_case([b for b in blocked if b])
        if worst:
            max_resp = max(worst, key=len)
            if max_resp:
                uncovered = [t for t in max_resp if t not in blocked]
                if uncovered:
                    decision.debate_log.append(f"Red-team: {len(uncovered)} uncovered: {uncovered}")
                    for ttp in uncovered:
                        decision.steps.append(DecisionStep(order=len(decision.steps)+1, action=DecisionAction.MONITOR, target=Entity(entity_type="technique", value=ttp), reason=f"Red-team uncovered: {ttp}", expected_effect=f"Monitor for {ttp}"))
                    decision.consensus_reached = False
        return decision

    def _initiate_debate(self, decision: DecisionScript, chain: AttackChain, correlation_id: Optional[str]) -> None:
        chain_ttps = [n.technique_id for n in chain.nodes]
        acts = [{"action": s.action.value, "expected_effect": s.expected_effect, "reason": s.reason, "target_ttp": s.expected_effect} for s in decision.steps]
        verdict = self._arbitrator.evaluate(round_num=1, chain_ttps=chain_ttps, defense_actions=acts, business_impact_score=decision.business_impact.score)
        decision.debate_log.append(f"Arbitration r1: accepted={verdict.defense_accepted}, coverage={verdict.coverage_score:.0%}")
        if verdict.defense_accepted:
            decision.consensus_reached = True
        else:
            decision.consensus_reached = False
            decision.debate_log.append(f"Insufficient: {verdict.reason}")
        self.publish_decision(decision, correlation_id or chain.chain_id)

    def on_debate(self, payload: dict[str, Any], correlation_id: Optional[str]) -> None:
        logger.info("Received debate response: %s", payload)