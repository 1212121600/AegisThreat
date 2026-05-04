"""WebSocket support for real-time dashboard updates.

Pushes AttackFragments, AttackChains, and DecisionScripts to connected
clients as they are produced by the agent pipeline.

Usage:
    ws://localhost:8000/ws — subscribe to all events
    ws://localhost:8000/ws?topics=fragment,chain — filter by event type
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

logger = logging.getLogger(__name__)

router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections and broadcasts events to clients."""

    def __init__(self) -> None:
        self._connections: dict[str, WebSocket] = {}
        self._id_counter: int = 0

    async def connect(self, websocket: WebSocket) -> str:
        await websocket.accept()
        self._id_counter += 1
        conn_id = f"ws-{self._id_counter}"
        self._connections[conn_id] = websocket
        logger.info("WebSocket connected: %s (total: %d)", conn_id, len(self._connections))
        return conn_id

    def disconnect(self, conn_id: str) -> None:
        self._connections.pop(conn_id, None)
        logger.info("WebSocket disconnected: %s (total: %d)", conn_id, len(self._connections))

    async def broadcast(self, event_type: str, payload: dict[str, Any]) -> None:
        """Broadcast an event to all connected clients."""
        message = json.dumps({
            "type": event_type,
            "payload": payload,
        }, default=str)

        dead: list[str] = []
        for conn_id, ws in self._connections.items():
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(conn_id)

        for conn_id in dead:
            self.disconnect(conn_id)

    async def broadcast_fragment(self, fragment: Any) -> None:
        payload = fragment.model_dump() if hasattr(fragment, 'model_dump') else fragment
        await self.broadcast("fragment", payload)

    async def broadcast_chain(self, chain: Any) -> None:
        payload = chain.model_dump() if hasattr(chain, 'model_dump') else chain
        await self.broadcast("chain", payload)

    async def broadcast_decision(self, decision: Any) -> None:
        payload = decision.model_dump() if hasattr(decision, 'model_dump') else decision
        await self.broadcast("decision", payload)

    @property
    def active_connections(self) -> int:
        return len(self._connections)


# Singleton connection manager
_ws_manager = ConnectionManager()


def get_ws_manager() -> ConnectionManager:
    return _ws_manager


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, topics: str = Query("")):
    """WebSocket endpoint for real-time event streaming.

    Query params:
        topics: Comma-separated list of event types to receive.
                Empty = all events. Example: ?topics=fragment,chain
    """
    conn_id = await _ws_manager.connect(websocket)
    filter_topics = set(t.strip() for t in topics.split(",") if t.strip()) if topics else None

    try:
        # Send initial connection confirmation
        await websocket.send_text(json.dumps({
            "type": "connected",
            "conn_id": conn_id,
            "message": "Connected to AegisThreat real-time feed",
        }))

        # Keep connection alive and listen for client messages
        while True:
            data = await websocket.receive_text()
            # Client can send ping or filter changes
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))

    except WebSocketDisconnect:
        _ws_manager.disconnect(conn_id)
    except Exception:
        logger.exception("WebSocket error for %s", conn_id)
        _ws_manager.disconnect(conn_id)
