"""ThreatBus — Kafka-based asynchronous message bus for Agent communication.

Topic layout:
  threat.fragment   — Detection Agent publishes AttackFragments
  threat.chain      — Tracing Agent publishes AttackChains
  threat.decision   — Defense Agent publishes DecisionScripts
  threat.debate     — Bi-directional debate between Defense and Tracing
  threat.heartbeat  — Liveness pings from all agents
  threat.command    — Command Center instructions to agents
"""

from __future__ import annotations

import json
import logging
import threading
import time
from abc import ABC, abstractmethod
from typing import Any, Callable, Optional

from aegis.core.models import ThreatEvent

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# Topic Constants
# ──────────────────────────────────────────────

class Topics:
    FRAGMENT = "threat.fragment"
    CHAIN = "threat.chain"
    DECISION = "threat.decision"
    DEBATE = "threat.debate"
    HEARTBEAT = "threat.heartbeat"
    COMMAND = "threat.command"
    DEAD_LETTER = "threat.dlq"

    ALL = [FRAGMENT, CHAIN, DECISION, DEBATE, HEARTBEAT, COMMAND, DEAD_LETTER]


# ──────────────────────────────────────────────
# Abstract Bus Interface
# ──────────────────────────────────────────────


class MessageBus(ABC):
    """Abstract interface for the ThreatBus.

    Implementations can use Kafka (production), in-memory queue (testing),
    or any other transport.
    """

    @abstractmethod
    def publish(self, topic: str, event: ThreatEvent) -> None:
        """Publish a ThreatEvent to the given topic."""
        ...

    @abstractmethod
    def subscribe(
        self, topic: str, callback: Callable[[ThreatEvent], None], group_id: str = ""
    ) -> None:
        """Subscribe to a topic with a callback handler."""
        ...

    @abstractmethod
    def dead_letter(self, event: ThreatEvent, reason: str = "") -> None:
        """Route a failed/unprocessable event to the Dead Letter Queue.

        Events in the DLQ are never silently dropped — they persist for
        manual inspection or automated retry.
        """
        ...

    @abstractmethod
    def close(self) -> None:
        """Gracefully close the bus connection."""
        ...


# ──────────────────────────────────────────────
# In-Memory Bus (for testing and single-node demo)
# ──────────────────────────────────────────────


class InMemoryBus(MessageBus):
    """Simple in-memory message bus for development, testing, and demos.

    Uses Python threading primitives — no external dependency required.
    Thread-safe for publish/subscribe.

    Dead Letter Queue: events that fail processing are stored in _dlq for
    later inspection. Call drain_dlq() to retrieve and clear them.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Callable[[ThreatEvent], None]]] = {}
        self._lock = threading.Lock()
        self._running = True
        self._dlq: list[tuple[ThreatEvent, str]] = []  # (event, reason)

    def publish(self, topic: str, event: ThreatEvent) -> None:
        if not self._running:
            logger.warning("Bus is shut down; dropping event %s", event.event_id)
            return
        logger.debug("Publishing %s to %s (corr=%s)", event.event_id, topic, event.correlation_id)
        with self._lock:
            subs = list(self._subscribers.get(topic, []))
        for callback in subs:
            try:
                callback(event)
            except Exception:
                logger.exception("Subscriber callback failed for event %s", event.event_id)

    def subscribe(
        self, topic: str, callback: Callable[[ThreatEvent], None], group_id: str = ""
    ) -> None:
        with self._lock:
            if topic not in self._subscribers:
                self._subscribers[topic] = []
            self._subscribers[topic].append(callback)
        logger.info("Subscribed to %s (group=%s)", topic, group_id or "default")

    def dead_letter(self, event: ThreatEvent, reason: str = "") -> None:
        """Route a failed event to the DLQ for manual inspection."""
        with self._lock:
            self._dlq.append((event, reason))
        logger.warning("Event %s routed to DLQ: %s", event.event_id, reason)

    def drain_dlq(self) -> list[tuple[ThreatEvent, str]]:
        """Retrieve and clear all DLQ events."""
        with self._lock:
            events = list(self._dlq)
            self._dlq.clear()
        return events

    def close(self) -> None:
        self._running = False
        with self._lock:
            self._subscribers.clear()
        logger.info("InMemoryBus shut down")


# ──────────────────────────────────────────────
# Kafka Bus (production)
# ──────────────────────────────────────────────


class KafkaBus(MessageBus):
    """Apache Kafka-backed ThreatBus for production deployments."""

    def __init__(self, bootstrap_servers: str, client_id: str = "aegis") -> None:
        self._bootstrap = bootstrap_servers
        self._client_id = client_id
        self._producer: Any = None
        self._consumers: list[Any] = []
        self._running = False
        self._init_kafka()

    def _init_kafka(self) -> None:
        try:
            from kafka import KafkaConsumer, KafkaProducer  # type: ignore[import-untyped]
        except ImportError:
            raise ImportError(
                "kafka-python is required for KafkaBus. Install with: pip install kafka-python"
            )
        self._producer = KafkaProducer(
            bootstrap_servers=self._bootstrap,
            client_id=self._client_id,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            acks="all",
            retries=3,
        )
        self._KafkaConsumer = KafkaConsumer
        self._running = True
        logger.info("KafkaBus connected to %s", self._bootstrap)

    def publish(self, topic: str, event: ThreatEvent) -> None:
        if not self._running or self._producer is None:
            logger.warning("KafkaBus not running; dropping event %s", event.event_id)
            return
        payload = event.model_dump(mode="json")
        self._producer.send(topic, value=payload)
        self._producer.flush(timeout=5)
        logger.debug("Published %s to Kafka topic %s", event.event_id, topic)

    def subscribe(
        self, topic: str, callback: Callable[[ThreatEvent], None], group_id: str = ""
    ) -> None:
        if not self._running:
            logger.error("KafkaBus not running; cannot subscribe to %s", topic)
            return
        consumer = self._KafkaConsumer(
            topic,
            bootstrap_servers=self._bootstrap,
            group_id=group_id or f"aegis-{topic}",
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            auto_offset_reset="latest",
            enable_auto_commit=True,
        )
        self._consumers.append(consumer)

        def _poll_loop() -> None:
            logger.info("Polling Kafka topic %s", topic)
            for msg in consumer:
                try:
                    event = ThreatEvent(**msg.value)
                    callback(event)
                except Exception:
                    logger.exception("Error processing Kafka message from %s", topic)

        t = threading.Thread(target=_poll_loop, daemon=True, name=f"kafka-{topic}")
        t.start()

    def dead_letter(self, event: ThreatEvent, reason: str = "") -> None:
        if not self._running or self._producer is None:
            logger.warning("KafkaBus not running; cannot DLQ event %s", event.event_id)
            return
        dlq_payload = event.model_dump(mode="json")
        dlq_payload["_dlq_reason"] = reason
        dlq_payload["_dlq_timestamp"] = time.time()
        self._producer.send(Topics.DEAD_LETTER, value=dlq_payload)
        self._producer.flush(timeout=5)
        logger.warning("Event %s routed to Kafka DLQ: %s", event.event_id, reason)

    def close(self) -> None:
        self._running = False
        if self._producer:
            self._producer.close()
        for consumer in self._consumers:
            consumer.close()
        logger.info("KafkaBus shut down")


# ──────────────────────────────────────────────
# Bus Factory
# ──────────────────────────────────────────────


def create_bus(backend: str = "memory", **kwargs: Any) -> MessageBus:
    """Factory to create the appropriate MessageBus implementation.

    Args:
        backend: "memory" for InMemoryBus, "kafka" for KafkaBus.
        **kwargs: Passed to the backend constructor
                  (e.g. bootstrap_servers for KafkaBus).
    """
    if backend == "kafka":
        return KafkaBus(**kwargs)
