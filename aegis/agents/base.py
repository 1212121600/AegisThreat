"""Base Agent class with ThreatBus lifecycle management.

Every agent (Detection, Tracing, Defense) inherits from BaseAgent, which
provides standardised publish/subscribe patterns, heartbeat, structured
logging, and graceful shutdown.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

from aegis.core.bus import MessageBus, Topics, create_bus
from aegis.core.models import AgentRole, EventType, ThreatEvent

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstract base for all AegisThreat agents.

    Subclasses must implement:
      - on_fragment(event): handle incoming AttackFragments
      - agent_role: return the AgentRole enum

    Optional overrides:
      - on_chain(event): handle incoming AttackChains (default: log)
      - on_decision(event): handle incoming DecisionScripts (default: log)
      - on_debate(event): handle debate messages (default: no-op)
      - on_command(event): handle Command Center instructions (default: log)
    """

    def __init__(
        self,
        agent_id: str = "",
        bus: Optional[MessageBus] = None,
        bus_backend: str = "memory",
        bus_kwargs: Optional[dict[str, Any]] = None,
    ) -> None:
        self.agent_id = agent_id or self._generate_id()
        self._bus = bus or create_bus(bus_backend, **(bus_kwargs or {}))
        self._running = False
        self._shutdown_event = threading.Event()

        # Statistics
        self.stats: dict[str, int] = {
            "messages_received": 0,
            "messages_published": 0,
            "errors": 0,
        }

    # ── Identity ──────────────────────────────

    @property
    @abstractmethod
    def agent_role(self) -> AgentRole:
        ...

    def _generate_id(self) -> str:
        import uuid
        role = self.agent_role.value if hasattr(self, "agent_role") else "agent"
        return f"{role}-{uuid.uuid4().hex[:8]}"

    # ── Lifecycle ────────────────────────────

    def start(self) -> None:
        """Start the agent: subscribe to topics and begin processing."""
        self._running = True
        self._setup_subscriptions()
        self._start_heartbeat()
        logger.info("[%s] Agent started (role=%s)", self.agent_id, self.agent_role.value)

    def stop(self) -> None:
        """Gracefully stop the agent."""
        self._running = False
        self._shutdown_event.set()
        self._bus.close()
        logger.info("[%s] Agent stopped. Stats: %s", self.agent_id, self.stats)

    def run_forever(self) -> None:
        """Start and block until SIGINT/SIGTERM."""
        self.start()
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def _signal_handler(self, signum: int, frame: Any) -> None:
        logger.info("[%s] Received signal %d, shutting down...", self.agent_id, signum)
        self._running = False
        self._shutdown_event.set()

    # ── Subscriptions ────────────────────────

    def _setup_subscriptions(self) -> None:
        """Set up topic subscriptions based on the agent's role."""
        role = self.agent_role

        # Every agent listens to commands
        self._bus.subscribe(Topics.COMMAND, self._handle_command, group_id=self.agent_id)

        # Role-specific subscriptions
        if role == AgentRole.DETECTION:
            # Detection Agent does not consume other agents' output by default
            pass
        elif role == AgentRole.TRACING:
            self._bus.subscribe(Topics.FRAGMENT, self._handle_fragment, group_id=self.agent_id)
            self._bus.subscribe(Topics.DEBATE, self._handle_debate, group_id=self.agent_id)
        elif role == AgentRole.DEFENSE:
            self._bus.subscribe(Topics.CHAIN, self._handle_chain, group_id=self.agent_id)
            self._bus.subscribe(Topics.DEBATE, self._handle_debate, group_id=self.agent_id)
        elif role == AgentRole.COMMAND:
            self._bus.subscribe(Topics.FRAGMENT, self._handle_fragment, group_id=self.agent_id)
            self._bus.subscribe(Topics.CHAIN, self._handle_chain, group_id=self.agent_id)
            self._bus.subscribe(Topics.DECISION, self._handle_decision, group_id=self.agent_id)

    def _start_heartbeat(self) -> None:
        """Publish a heartbeat every 30 seconds."""

        def _beat() -> None:
            while self._running and not self._shutdown_event.wait(30):
                event = ThreatEvent(
                    event_type=EventType.HEARTBEAT,
                    producer=self.agent_role,
                    payload={"agent_id": self.agent_id, "stats": self.stats},
                )
                self._bus.publish(Topics.HEARTBEAT, event)

        t = threading.Thread(target=_beat, daemon=True, name=f"{self.agent_id}-heartbeat")
        t.start()

    # ── Message Handlers ─────────────────────

    def _handle_fragment(self, event: ThreatEvent) -> None:
        self.stats["messages_received"] += 1
        try:
            from aegis.core.models import AttackFragment
            fragment = AttackFragment(**event.payload) if isinstance(event.payload, dict) else event.payload
            self.on_fragment(fragment, event.correlation_id)
        except Exception:
            logger.exception("[%s] Error handling fragment", self.agent_id)
            self.stats["errors"] += 1
            self._bus.dead_letter(event, f"{self.agent_id}: fragment processing failed")

    def _handle_chain(self, event: ThreatEvent) -> None:
        self.stats["messages_received"] += 1
        try:
            from aegis.core.models import AttackChain
            chain = AttackChain(**event.payload) if isinstance(event.payload, dict) else event.payload
            self.on_chain(chain, event.correlation_id)
        except Exception:
            logger.exception("[%s] Error handling chain", self.agent_id)
            self.stats["errors"] += 1
            self._bus.dead_letter(event, f"{self.agent_id}: chain processing failed")

    def _handle_decision(self, event: ThreatEvent) -> None:
        self.stats["messages_received"] += 1
        try:
            from aegis.core.models import DecisionScript
            decision = DecisionScript(**event.payload) if isinstance(event.payload, dict) else event.payload
            self.on_decision(decision, event.correlation_id)
        except Exception:
            logger.exception("[%s] Error handling decision", self.agent_id)
            self.stats["errors"] += 1
            self._bus.dead_letter(event, f"{self.agent_id}: decision processing failed")

    def _handle_debate(self, event: ThreatEvent) -> None:
        self.stats["messages_received"] += 1
        try:
            self.on_debate(event.payload if isinstance(event.payload, dict) else event.payload, event.correlation_id)
        except Exception:
            logger.exception("[%s] Error handling debate", self.agent_id)
            self.stats["errors"] += 1
            self._bus.dead_letter(event, f"{self.agent_id}: debate processing failed")

    def _handle_command(self, event: ThreatEvent) -> None:
        self.stats["messages_received"] += 1
        try:
            self.on_command(event.payload, event.correlation_id)
        except Exception:
            logger.exception("[%s] Error handling command", self.agent_id)
            self.stats["errors"] += 1
            self._bus.dead_letter(event, f"{self.agent_id}: command processing failed")

    # ── Overridable Handlers ──────

    def on_fragment(self, fragment: Any, correlation_id: Optional[str]) -> None:
        """Process an incoming AttackFragment. Override in Tracing agent."""
        logger.debug("[%s] Received fragment %s", self.agent_id, getattr(fragment, 'fragment_id', '?'))

    def on_chain(self, chain: Any, correlation_id: Optional[str]) -> None:
        """Process an incoming AttackChain. Override in Tracing/Defense agents."""
        logger.debug("[%s] Received chain %s", self.agent_id, getattr(chain, 'chain_id', '?'))

    def on_decision(self, decision: Any, correlation_id: Optional[str]) -> None:
        """Process an incoming DecisionScript. Override in Command Center."""
        logger.debug("[%s] Received decision %s", self.agent_id, getattr(decision, 'decision_id', '?'))

    def on_debate(self, payload: dict[str, Any], correlation_id: Optional[str]) -> None:
        """Process a debate message. Override in Tracing/Defense agents."""
        logger.debug("[%s] Received debate message (corr=%s)", self.agent_id, correlation_id)

    def on_command(self, payload: dict[str, Any], correlation_id: Optional[str]) -> None:
        """Process a command from the Command Center."""
        logger.info("[%s] Received command: %s", self.agent_id, payload)

    # ── Publishing Helpers ───────────────────

    def _publish(self, event_type: EventType, topic: str, payload: Any, correlation_id: Optional[str] = None) -> ThreatEvent:
        """Create and publish a ThreatEvent envelope."""
        event = ThreatEvent(
            event_type=event_type,
            producer=self.agent_role,
            correlation_id=correlation_id,
            payload=payload,
        )
        self._bus.publish(topic, event)
        self.stats["messages_published"] += 1
        return event

    def publish_fragment(self, fragment: Any, correlation_id: Optional[str] = None) -> ThreatEvent:
        return self._publish(EventType.FRAGMENT, Topics.FRAGMENT, fragment, correlation_id)

    def publish_chain(self, chain: Any, correlation_id: Optional[str] = None) -> ThreatEvent:
        return self._publish(EventType.CHAIN, Topics.CHAIN, chain, correlation_id)

    def publish_decision(self, decision: Any, correlation_id: Optional[str] = None) -> ThreatEvent:
        return self._publish(EventType.DECISION, Topics.DECISION, decision, correlation_id)

    def publish_debate(self, payload: dict[str, Any], correlation_id: Optional[str] = None) -> ThreatEvent:
        return self._publish(EventType.DEBATE, Topics.DEBATE, payload, correlation_id)