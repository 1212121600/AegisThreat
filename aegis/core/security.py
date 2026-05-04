"""Message integrity and security utilities for ThreatBus.

Implements HMAC signing for ThreatEvent messages to prevent:
- Message tampering: an attacker modifying Fragment/Chain/Decision in transit
- Message injection: an attacker publishing fake events to the bus
- Replay attacks: an attacker replaying old events to trigger wrong actions

For production: integrate with a proper KMS (AWS KMS, HashiCorp Vault).
For MVP: HMAC-SHA256 with a shared secret from config/env.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from typing import Any, Optional

from aegis.core.models import ThreatEvent

logger = logging.getLogger(__name__)


class MessageSigner:
    """HMAC-based message signing for ThreatEvent integrity verification.

    Every event published to the ThreatBus MUST carry a signature.
    Every consumer MUST verify the signature before processing.
    """

    def __init__(self, secret: str = "") -> None:
        """
        Args:
            secret: HMAC shared secret (from AEGIS_SIGNING_SECRET env var).
        """
        self._secret = secret.encode("utf-8") if secret else b""
        self._enabled = bool(secret)

    @property
    def enabled(self) -> bool:
        return self._enabled

    def sign_event(self, event: ThreatEvent) -> ThreatEvent:
        """Sign a ThreatEvent by adding an HMAC to its trace_context.

        The signature covers: event_id + event_type + timestamp + payload.
        This prevents tampering with any of these fields in transit.
        """
        if not self._enabled:
            return event

        payload = self._canonical_payload(event)
        signature = hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()

        event.trace_context = event.trace_context or {}
        event.trace_context["signature"] = signature
        event.trace_context["signature_version"] = "hmac-sha256-v1"

        return event

    def verify_event(self, event: ThreatEvent) -> bool:
        """Verify the HMAC signature on a ThreatEvent.

        Returns True if the signature is valid or signing is disabled,
        False if the signature is missing or invalid.
        """
        if not self._enabled:
            return True

        sig = (event.trace_context or {}).get("signature", "")
        if not sig:
            logger.warning("Missing signature on event %s", event.event_id)
            return False

        payload = self._canonical_payload(event)
        expected = hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected, sig):
            logger.warning("Invalid signature on event %s", event.event_id)
            return False

        return True

    @staticmethod
    def _canonical_payload(event: ThreatEvent) -> str:
        """Create a canonical string for signing."""
        # Use a stable subset of fields
        canonical = json.dumps({
            "event_id": event.event_id,
            "event_type": event.event_type.value,
            "timestamp": event.timestamp.isoformat(),
            "payload": event.payload.model_dump(mode="json") if hasattr(event.payload, 'model_dump') else event.payload,
        }, sort_keys=True, default=str)
        return canonical


class ReplayProtection:
    """Nonce-based replay protection for ThreatEvent messages.

    Tracks recently-seen event IDs within a sliding window to prevent
    an attacker from replaying old (but validly-signed) events.
    """

    def __init__(self, window_seconds: int = 3600, max_cache_size: int = 100000) -> None:
        self._window = window_seconds
        self._max_cache = max_cache_size
        self._seen: dict[str, float] = {}  # event_id → seen_at (unix timestamp)

    def is_replay(self, event: ThreatEvent) -> bool:
        """Check if this event has already been processed.

        Returns True if this is a replay (should be rejected),
        False if it's new (should be processed).
        """
        now = time.time()

        # Prune expired entries
        cutoff = now - self._window
        expired = [eid for eid, ts in self._seen.items() if ts < cutoff]
        for eid in expired:
            del self._seen[eid]

        # Cache overflow protection
        if len(self._seen) > self._max_cache:
            # Remove oldest half
            sorted_ids = sorted(self._seen.items(), key=lambda x: x[1])
            for eid, _ in sorted_ids[:len(sorted_ids) // 2]:
                del self._seen[eid]

        if event.event_id in self._seen:
            logger.warning("Replay detected: event %s already processed", event.event_id)
            return True

        self._seen[event.event_id] = now
        return False

    def reset(self) -> None:
        self._seen.clear()


class SecureBusWrapper:
    """Wraps a MessageBus with signing + replay protection.

    Usage:
        raw_bus = create_bus("kafka", bootstrap_servers="...")
        secure_bus = SecureBusWrapper(raw_bus, signer, replay_protection)
        agent = DetectionAgent(bus=secure_bus)  # Drop-in replacement
    """

    def __init__(
        self,
        inner_bus: Any,
        signer: Optional[MessageSigner] = None,
        replay_protection: Optional[ReplayProtection] = None,
    ) -> None:
        self._bus = inner_bus
        self._signer = signer or MessageSigner()
        self._replay = replay_protection or ReplayProtection()

    def publish(self, topic: str, event: ThreatEvent) -> None:
        event = self._signer.sign_event(event)
        self._bus.publish(topic, event)

    def subscribe(
        self, topic: str, callback: Any, group_id: str = ""
    ) -> None:
        def _verified_callback(event: ThreatEvent) -> None:
            if not self._signer.verify_event(event):
                self._bus.dead_letter(event, "signature verification failed")
                return
            if self._replay.is_replay(event):
                self._bus.dead_letter(event, "replay detected")
                return
            callback(event)

        self._bus.subscribe(topic, _verified_callback, group_id)

    def dead_letter(self, event: ThreatEvent, reason: str = "") -> None:
        self._bus.dead_letter(event, reason)

    def close(self) -> None:
        self._bus.close()
