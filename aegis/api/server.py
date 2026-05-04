"""FastAPI server for AegisThreat Command Center - v2."""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, Optional

from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ValidationError

from aegis.core.bus import InMemoryBus, MessageBus
from aegis.core.models import AttackChain, AttackFragment, DecisionScript, EventType, ThreatEvent
from aegis.core.persistence import PersistenceStore
from aegis.agents.detection import DetectionAgent
from aegis.agents.tracing import TracingAgent
from aegis.agents.defense import DefenseAgent
from aegis.api.auth import require_auth
from aegis.api.websocket import get_ws_manager
from aegis.api.routes import fragments as fragment_routes
from aegis.api.routes import chains as chain_routes
from aegis.api.routes import decisions as decision_routes

logger = logging.getLogger(__name__)

_store: Optional[PersistenceStore] = None
_bus: Optional[MessageBus] = None
_detection: Optional[DetectionAgent] = None
_tracing: Optional[TracingAgent] = None
_defense: Optional[DefenseAgent] = None
_fragments: dict[str, AttackFragment] = {}
_chains: dict[str, AttackChain] = {}
_decisions: dict[str, DecisionScript] = {}
_events: list[ThreatEvent] = []

def get_store() -> PersistenceStore:
    assert _store is not None
    return _store

def _on_fragment_event(event: ThreatEvent) -> None:
    frag = AttackFragment(**event.payload) if isinstance(event.payload, dict) else event.payload
    _fragments[frag.fragment_id] = frag
    _events.append(event)
    if _store:
        _store.save_fragment(frag)
        _store.save_event(event)
        _store.audit("detection", "fragment_generated", {"fragment_id": frag.fragment_id})
    try:
        import asyncio
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(get_ws_manager().broadcast_fragment(frag))
    except Exception:
        pass

def _on_chain_event(event: ThreatEvent) -> None:
    chain = AttackChain(**event.payload) if isinstance(event.payload, dict) else event.payload
    _chains[chain.chain_id] = chain
    _events.append(event)
    if _store:
        _store.save_chain(chain)
        _store.save_event(event)
    try:
        import asyncio
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(get_ws_manager().broadcast_chain(chain))
    except Exception:
        pass

def _on_decision_event(event: ThreatEvent) -> None:
    dec = DecisionScript(**event.payload) if isinstance(event.payload, dict) else event.payload
    _decisions[dec.decision_id] = dec
    _events.append(event)
    if _store:
        _store.save_decision(dec)
        _store.save_event(event)
    try:
        import asyncio
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(get_ws_manager().broadcast_decision(dec))
    except Exception:
        pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _store, _bus, _detection, _tracing, _defense
    db_path = os.environ.get("AEGIS_DB_PATH", "data/aegis.db")
    _store = PersistenceStore(db_path)
    for f_data in _store.list_fragments(limit=500):
        try: _fragments[f_data["fragment_id"]] = AttackFragment(**f_data)
        except Exception: pass
    for c_data in _store.list_chains(limit=500):
        try: _chains[c_data["chain_id"]] = AttackChain(**c_data)
        except Exception: pass
    for d_data in _store.list_decisions(limit=500):
        try: _decisions[d_data["decision_id"]] = DecisionScript(**d_data)
        except Exception: pass
    logger.info("Restored %d fragments, %d chains, %d decisions", len(_fragments), len(_chains), len(_decisions))
    _bus = InMemoryBus()
    _bus.subscribe("threat.fragment", _on_fragment_event)
    _bus.subscribe("threat.chain", _on_chain_event)
    _bus.subscribe("threat.decision", _on_decision_event)
    _detection = DetectionAgent(bus=_bus)
    _tracing = TracingAgent(bus=_bus)
    _defense = DefenseAgent(bus=_bus)
    _detection.start(); _tracing.start(); _defense.start()
    logger.info("AegisThreat API v2 started (persistence=%s)", db_path)
    yield
    _defense.stop(); _tracing.stop(); _detection.stop()

app = FastAPI(title="AegisThreat API", version="0.2.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(fragment_routes.router)
app.include_router(chain_routes.router)
app.include_router(decision_routes.router)
from aegis.api.websocket import router as ws_router
app.include_router(ws_router)

class AlertRequest(BaseModel):
    model_config = {"extra": "ignore"}
    timestamp: Optional[str] = None
    rule_name: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    action: str = ""
    artifact: Optional[str] = None
    severity: str = "medium"
    domain: Optional[str] = None
    raw_log: Optional[str] = None

class StatsResponse(BaseModel):
    fragments_count: int
    chains_count: int
    decisions_count: int
    events_count: int
    db_stats: dict[str, int] = Field(default_factory=dict)

@app.post("/alerts", status_code=202)
async def ingest_alert(request: Request):
    if _detection is None:
        raise HTTPException(500, "Detection Agent not initialized")
    body = await request.json()
    try:
        alert = AlertRequest(**body)
    except ValidationError as e:
        raise HTTPException(422, detail=json.loads(e.json()))
    fragment = _detection.ingest_and_publish(alert.model_dump())
    result = {"accepted": True, "alert": alert.rule_name}
    if fragment:
        result.update(fragment_id=fragment.fragment_id, fragment_summary=fragment.summary, confidence=fragment.confidence)
    else:
        result.update(fragment_triggered=False, message="Alert buffered")
    return result

@app.post("/alerts/batch", status_code=202)
async def ingest_alerts_batch(request: Request):
    if _detection is None:
        raise HTTPException(500, "Detection Agent not initialized")
    body = await request.json()
    if not isinstance(body, list):
        raise HTTPException(422, "Expected JSON array")
    results = []
    for item in body:
        try:
            alert = AlertRequest(**item)
        except ValidationError as e:
            raise HTTPException(422, detail=json.loads(e.json()))
        fragment = _detection.ingest_and_publish(alert.model_dump())
        r = {"alert": alert.rule_name, "fragment_triggered": fragment is not None}
        if fragment:
            r["fragment_id"] = fragment.fragment_id
        results.append(r)
    return {"accepted": len(results), "results": results}

@app.get("/stats", response_model=StatsResponse)
async def get_stats():
    db_stats = _store.get_stats() if _store else {}
    return StatsResponse(fragments_count=len(_fragments), chains_count=len(_chains), decisions_count=len(_decisions), events_count=len(_events), db_stats=db_stats)

@app.get("/health")
async def health_check():
    ws = get_ws_manager().active_connections
    return {"status": "healthy", "version": "0.2.0", "websocket_connections": ws}

@app.get("/audit")
async def get_audit_log(agent: str = "", limit: int = 100):
    if not _store:
        return {"entries": []}
    entries = _store.get_audit_log(agent=agent, limit=limit)
    return {"entries": entries, "count": len(entries)}

def get_fragments_store() -> dict[str, AttackFragment]:
    return _fragments

def get_chains_store() -> dict[str, AttackChain]:
    return _chains

def get_decisions_store() -> dict[str, DecisionScript]:
    return _decisions

def main() -> None:
    import uvicorn
    uvicorn.run("aegis.api.server:app", host="0.0.0.0", port=8000, reload=True)

if __name__ == "__main__":
    main()
