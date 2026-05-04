"""SQLite persistence layer for AegisThreat.

Stores AttackFragments, AttackChains, and DecisionScripts with full
provenance so data survives API server restarts.

Uses only the Python standard library (sqlite3) — zero external deps.
Modeled on the same pattern as ServiceAgent's ticket storage.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS fragments (
    fragment_id TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL,
    confidence REAL DEFAULT 0.0,
    alert_count INTEGER DEFAULT 0,
    ts_start TEXT NOT NULL,
    ts_end TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS chains (
    chain_id TEXT PRIMARY KEY,
    fragment_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    overall_confidence REAL DEFAULT 0.0,
    step_count INTEGER DEFAULT 0,
    techniques_json TEXT DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (fragment_id) REFERENCES fragments(fragment_id)
);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id TEXT PRIMARY KEY,
    chain_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    business_impact_score INTEGER DEFAULT 0,
    step_count INTEGER DEFAULT 0,
    consensus_reached INTEGER DEFAULT 0,
    approved_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (chain_id) REFERENCES chains(chain_id)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_json TEXT NOT NULL,
    event_type TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent TEXT NOT NULL,
    action TEXT NOT NULL,
    details_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_fragments_ts ON fragments(ts_start);
CREATE INDEX IF NOT EXISTS idx_fragments_confidence ON fragments(confidence);
CREATE INDEX IF NOT EXISTS idx_chains_fragment ON chains(fragment_id);
CREATE INDEX IF NOT EXISTS idx_chains_confidence ON chains(overall_confidence);
CREATE INDEX IF NOT EXISTS idx_decisions_chain ON decisions(chain_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent);
"""


class PersistenceStore:
    """Thread-safe SQLite-backed persistence for all AegisThreat data.

    Usage:
        store = PersistenceStore("data/aegis.db")
        store.save_fragment(fragment)
        fragments = store.list_fragments(limit=50)
    """

    def __init__(self, db_path: str = "data/aegis.db") -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._get_conn() as conn:
            conn.executescript(SCHEMA_SQL)
            conn.commit()
        logger.info("PersistenceStore initialized at %s", self._db_path)

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    # ── Fragments ────────────────────────────

    def save_fragment(self, fragment: Any) -> bool:
        """Save an AttackFragment. Returns True on success."""
        try:
            payload = fragment.model_dump(mode="json") if hasattr(fragment, 'model_dump') else fragment
            ts_start = str(payload.get("timestamp_span", [None, None])[0] or "")
            ts_end = str(payload.get("timestamp_span", [None, None])[1] or "")
            with self._lock, self._get_conn() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO fragments (fragment_id, payload_json, confidence, alert_count, ts_start, ts_end) VALUES (?, ?, ?, ?, ?, ?)",
                    (fragment.fragment_id, json.dumps(payload, default=str), getattr(fragment, 'confidence', 0),
                     getattr(fragment, 'raw_alert_count', 0), ts_start, ts_end),
                )
                conn.commit()
            return True
        except Exception:
            logger.exception("Failed to save fragment %s", getattr(fragment, 'fragment_id', '?'))
            return False

    def get_fragment(self, fragment_id: str) -> Optional[dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            row = conn.execute("SELECT payload_json FROM fragments WHERE fragment_id = ?", (fragment_id,)).fetchone()
            if row:
                return json.loads(row["payload_json"])
        return None

    def list_fragments(self, limit: int = 50, min_confidence: float = 0.0) -> list[dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM fragments WHERE confidence >= ? ORDER BY created_at DESC LIMIT ?",
                (min_confidence, limit),
            ).fetchall()
        return [json.loads(r["payload_json"]) for r in rows]

    def count_fragments(self) -> int:
        with self._lock, self._get_conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM fragments").fetchone()[0]

    # ── Chains ───────────────────────────────

    def save_chain(self, chain: Any) -> bool:
        try:
            payload = chain.model_dump(mode="json") if hasattr(chain, 'model_dump') else chain
            techniques = [n.get("technique_id", "") for n in payload.get("nodes", [])]
            with self._lock, self._get_conn() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO chains (chain_id, fragment_id, payload_json, overall_confidence, step_count, techniques_json) VALUES (?, ?, ?, ?, ?, ?)",
                    (chain.chain_id, getattr(chain, 'fragment_id', ''), json.dumps(payload, default=str),
                     getattr(chain, 'overall_confidence', 0), getattr(chain, 'step_count', 0),
                     json.dumps(techniques)),
                )
                conn.commit()
            return True
        except Exception:
            logger.exception("Failed to save chain %s", getattr(chain, 'chain_id', '?'))
            return False

    def get_chain(self, chain_id: str) -> Optional[dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            row = conn.execute("SELECT payload_json FROM chains WHERE chain_id = ?", (chain_id,)).fetchone()
            return json.loads(row["payload_json"]) if row else None

    def list_chains(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM chains ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(r["payload_json"]) for r in rows]

    def get_chains_for_fragment(self, fragment_id: str) -> list[dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM chains WHERE fragment_id = ? ORDER BY created_at DESC", (fragment_id,)
            ).fetchall()
        return [json.loads(r["payload_json"]) for r in rows]

    # ── Decisions ────────────────────────────

    def save_decision(self, decision: Any) -> bool:
        try:
            payload = decision.model_dump(mode="json") if hasattr(decision, 'model_dump') else decision
            with self._lock, self._get_conn() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO decisions (decision_id, chain_id, payload_json, business_impact_score, step_count, consensus_reached, approved_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (decision.decision_id, getattr(decision, 'chain_id', ''),
                     json.dumps(payload, default=str),
                     getattr(decision.business_impact, 'score', 0) if hasattr(decision, 'business_impact') else 0,
                     getattr(decision, 'step_count', 0),
                     1 if getattr(decision, 'consensus_reached', False) else 0,
                     getattr(decision, 'approved_by', None)),
                )
                conn.commit()
            return True
        except Exception:
            logger.exception("Failed to save decision %s", getattr(decision, 'decision_id', '?'))
            return False

    def get_decision(self, decision_id: str) -> Optional[dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            row = conn.execute("SELECT payload_json FROM decisions WHERE decision_id = ?", (decision_id,)).fetchone()
            return json.loads(row["payload_json"]) if row else None

    def list_decisions(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM decisions ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(r["payload_json"]) for r in rows]

    def approve_decision(self, decision_id: str, approved_by: str) -> bool:
        with self._lock, self._get_conn() as conn:
            conn.execute(
                "UPDATE decisions SET approved_by = ? WHERE decision_id = ?",
                (approved_by, decision_id),
            )
            conn.commit()
            return conn.total_changes > 0

    # ── Events ───────────────────────────────

    def save_event(self, event: Any) -> bool:
        try:
            payload = event.model_dump(mode="json") if hasattr(event, 'model_dump') else event
            with self._lock, self._get_conn() as conn:
                conn.execute(
                    "INSERT INTO events (event_json, event_type) VALUES (?, ?)",
                    (json.dumps(payload, default=str), getattr(event, 'event_type', 'unknown')),
                )
                conn.commit()
            return True
        except Exception:
            return False

    def list_events(self, limit: int = 100, event_type: str = "") -> list[dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            if event_type:
                rows = conn.execute(
                    "SELECT event_json FROM events WHERE event_type = ? ORDER BY created_at DESC LIMIT ?",
                    (event_type, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT event_json FROM events ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()
        return [json.loads(r["event_json"]) for r in rows]

    # ── Audit ────────────────────────────────

    def audit(self, agent: str, action: str, details: Optional[dict[str, Any]] = None) -> None:
        with self._lock, self._get_conn() as conn:
            conn.execute(
                "INSERT INTO audit_log (agent, action, details_json) VALUES (?, ?, ?)",
                (agent, action, json.dumps(details or {}, default=str)),
            )
            conn.commit()

    def get_audit_log(self, agent: str = "", limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            if agent:
                rows = conn.execute(
                    "SELECT * FROM audit_log WHERE agent = ? ORDER BY created_at DESC LIMIT ?",
                    (agent, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()
        return [dict(r) for r in rows]

    # ── Stats ────────────────────────────────

    def get_stats(self) -> dict[str, int]:
        with self._lock, self._get_conn() as conn:
            return {
                "fragments": conn.execute("SELECT COUNT(*) FROM fragments").fetchone()[0],
                "chains": conn.execute("SELECT COUNT(*) FROM chains").fetchone()[0],
                "decisions": conn.execute("SELECT COUNT(*) FROM decisions").fetchone()[0],
                "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                "audit_entries": conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0],
            }
