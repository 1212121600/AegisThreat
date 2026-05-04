"""Core domain models for AegisThreat agent communication.

Defines the canonical data structures that flow through the ThreatBus:
  AttackFragment  →  AttackChain  →  DecisionScript
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


# ──────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────


class ConfidenceLevel(str, Enum):
    LOW = "low"           # < 0.5
    MEDIUM = "medium"     # 0.5 - 0.8
    HIGH = "high"         # >= 0.8


class EventType(str, Enum):
    FRAGMENT = "fragment"
    CHAIN = "chain"
    DECISION = "decision"
    DEBATE = "debate"
    HEARTBEAT = "heartbeat"
    ACK = "ack"


class AgentRole(str, Enum):
    DETECTION = "detection"
    TRACING = "tracing"
    DEFENSE = "defense"
    COMMAND = "command"


class DecisionAction(str, Enum):
    BLOCK_IP = "block_ip"
    BLOCK_PORT = "block_port"
    BLOCK_DOMAIN = "block_domain"
    ISOLATE_HOST = "isolate_host"
    KILL_PROCESS = "kill_process"
    DISABLE_ACCOUNT = "disable_account"
    DEPLOY_HONEYPOT = "deploy_honeypot"
    QUARANTINE_FILE = "quarantine_file"
    RESET_CREDENTIAL = "reset_credential"
    ENABLE_MFA = "enable_mfa"
    SEGMENT_NETWORK = "segment_network"
    MONITOR = "monitor"


# ──────────────────────────────────────────────
# Core Entities
# ──────────────────────────────────────────────


class Entity(BaseModel):
    """A named entity involved in an attack (host, IP, user, hash, domain, etc.)."""

    entity_type: str = Field(..., description="host, ip, user, hash, domain, process, file")
    value: str = Field(..., description="The actual identifier value")
    metadata: dict[str, Any] = Field(default_factory=dict)


class TTPMapping(BaseModel):
    """An ATT&CK technique mapped to an observed behavior."""

    technique_id: str = Field(..., description="e.g. T1110 (Brute Force)")
    technique_name: str = Field("")
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str = Field("", description="Why this TTP is suspected")
    sub_technique_id: Optional[str] = None


# ──────────────────────────────────────────────
# Attack Fragment (Detect Agent → ThreatBus)
# ──────────────────────────────────────────────


class AttackFragment(BaseModel):
    """Output of the Detection Agent — an aggregated alert cluster.

    Represents a coherent set of suspicious activities within a time window,
    mapped to suspected ATT&CK TTPs with confidence scoring.
    """

    fragment_id: str = Field(
        default_factory=lambda: f"frag-{uuid.uuid4().hex[:12]}"
    )
    entities: list[Entity] = Field(default_factory=list)
    summary: str = Field("", description="Natural-language summary of the alert cluster")
    suspected_ttps: list[TTPMapping] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_level: ConfidenceLevel = ConfidenceLevel.LOW
    timestamp_span: tuple[datetime, datetime] = Field(
        description="(start, end) of the observation window"
    )
    raw_alert_count: int = Field(default=0)
    correlation_id: Optional[str] = Field(default=None)

    @field_validator("confidence_level", mode="before")
    @classmethod
    def derive_level(cls, v: Any, info: Any) -> ConfidenceLevel:
        if isinstance(v, ConfidenceLevel):
            return v
        conf = info.data.get("confidence", 0)
        if conf >= 0.8:
            return ConfidenceLevel.HIGH
        if conf >= 0.5:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW

    def to_summary_string(self) -> str:
        ttps = ", ".join(t.technique_id for t in self.suspected_ttps[:5])
        entities_str = ", ".join(f"{e.entity_type}:{e.value}" for e in self.entities[:5])
        return (
            f"[{self.fragment_id}] conf={self.confidence:.2f} "
            f"entities=[{entities_str}] ttps=[{ttps}] — {self.summary[:120]}"
        )


# ──────────────────────────────────────────────
# Attack Chain (Tracing Agent → ThreatBus)
# ──────────────────────────────────────────────


class ChainNode(BaseModel):
    """A node (step) in the attack chain."""

    step: int = Field(ge=0)
    technique_id: str
    technique_name: str = ""
    tactic: str = Field("", description="ATT&CK tactic (e.g. Initial Access)")
    description: str = ""
    evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    entities_involved: list[Entity] = Field(default_factory=list)
    timestamp_estimate: Optional[datetime] = None
    is_predicted: bool = Field(
        default=False, description="Predicted next step (not yet observed)"
    )


class ChainEdge(BaseModel):
    """An edge connecting two steps, with relationship type."""

    from_step: int
    to_step: int
    relation: str = Field(
        default="followed_by",
        description="e.g. followed_by, requires, enables, variant_of",
    )
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    reasoning: str = ""


class AttackChain(BaseModel):
    """Output of the Tracing Agent — the full inferred attack chain."""

    chain_id: str = Field(
        default_factory=lambda: f"chain-{uuid.uuid4().hex[:12]}"
    )
    fragment_id: str = Field("", description="Source fragment that triggered this chain")
    nodes: list[ChainNode] = Field(default_factory=list)
    edges: list[ChainEdge] = Field(default_factory=list)
    overall_confidence: float = Field(ge=0.0, le=1.0)
    confidence_level: ConfidenceLevel = ConfidenceLevel.LOW
    predicted_next_steps: list[ChainNode] = Field(default_factory=list)
    reasoning_log: list[str] = Field(
        default_factory=list, description="Step-by-step reasoning trace"
    )
    kibana_timeline_url: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def step_count(self) -> int:
        return len(self.nodes)

    @property
    def predicted_step_count(self) -> int:
        return sum(1 for n in self.nodes if n.is_predicted)

    def to_summary_string(self) -> str:
        path = " → ".join(
            n.technique_id for n in sorted(self.nodes, key=lambda n: n.step)
        )
        pred = " → ".join(p.technique_id for p in self.predicted_next_steps)
        return (
            f"[{self.chain_id}] confidence={self.overall_confidence:.2f} "
            f"steps={self.step_count} chain=[{path}] "
            f"predicted=[{pred}]"
        )


# ──────────────────────────────────────────────
# Decision Script (Defense Agent → ThreatBus)
# ──────────────────────────────────────────────


class DecisionStep(BaseModel):
    """A single defensive action within a DecisionScript."""

    order: int = Field(ge=1)
    action: DecisionAction
    target: Entity
    reason: str = ""
    expected_effect: str = Field(
        "", description="What TTP or attack step this action should block"
    )
    rollback_action: Optional[DecisionAction] = Field(
        default=None, description="How to undo this action if needed"
    )
    pre_check: Optional[str] = Field(
        default=None, description="Condition to verify before executing"
    )


class BusinessImpact(BaseModel):
    """Estimated business impact of a defensive action or entire script."""

    score: int = Field(default=50, ge=1, le=100, description="1=no impact, 100=total outage")
    affected_services: list[str] = Field(default_factory=list)
    affected_user_count: int = Field(default=0)
    estimated_downtime_minutes: int = Field(default=0)
    justification: str = ""


class DecisionScript(BaseModel):
    """Output of the Defense Agent — the recommended defensive playbook.

    Contains ordered defensive actions with rationale, impact assessment,
    and a record of the debate that produced this consensus.
    """

    decision_id: str = Field(
        default_factory=lambda: f"dec-{uuid.uuid4().hex[:12]}"
    )
    chain_id: str = ""
    steps: list[DecisionStep] = Field(default_factory=list)
    business_impact: BusinessImpact = Field(default_factory=BusinessImpact)
    debate_log: list[str] = Field(
        default_factory=list, description="Rounds of debate between Defense and Tracing agents"
    )
    consensus_reached: bool = Field(default=False)
    requires_human_approval: bool = Field(default=True)
    approved_by: Optional[str] = None
    executed_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def step_count(self) -> int:
        return len(self.steps)

    def to_summary_string(self) -> str:
        actions = " → ".join(s.action.value for s in self.steps)
        return (
            f"[{self.decision_id}] chain={self.chain_id} "
            f"steps={self.step_count} actions=[{actions}] "
            f"impact={self.business_impact.score}/100 "
            f"consensus={'yes' if self.consensus_reached else 'no'}"
        )


# ──────────────────────────────────────────────
# Threat Event Protocol (TEP) Envelope
# ──────────────────────────────────────────────


class ThreatEvent(BaseModel):
    """The standard envelope for all messages on the ThreatBus.

    Every message flowing between agents, or between agents and the Command
    Center, is wrapped in this envelope. The payload field contains one of
    AttackFragment, AttackChain, or DecisionScript depending on event_type.
    """

    event_id: str = Field(
        default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}"
    )
    event_type: EventType
    producer: AgentRole
    correlation_id: Optional[str] = Field(
        default=None,
        description="Links events across agents for the same incident",
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ttl_seconds: int = Field(default=3600, description="Time-to-live in seconds")
    priority: int = Field(default=3, ge=1, le=5, description="1=low, 5=critical")
    schema_version: str = Field(default="1.0.0")
    payload: AttackFragment | AttackChain | DecisionScript | dict[str, Any] = Field(
        default_factory=dict
    )
    trace_context: dict[str, str] = Field(
        default_factory=dict,
        description="OpenTelemetry-style trace context for debugging",
    )

    def is_expired(self) -> bool:
        age = (datetime.now(timezone.utc) - self.timestamp).total_seconds()
        return age > self.ttl_seconds
