"""Attack Chain API routes."""

from fastapi import APIRouter, HTTPException, Query

router = APIRouter(prefix="/chains", tags=["chains"])


def _get_store():
    from aegis.api.server import get_chains_store
    return get_chains_store()


@router.get("")
def list_chains(limit: int = Query(50, ge=1, le=500)):
    store = _get_store()
    items = sorted(store.values(), key=lambda c: c.created_at, reverse=True)
    return [c.model_dump() for c in items[:limit]]


@router.get("/{chain_id}")
def get_chain(chain_id: str):
    store = _get_store()
    chain = store.get(chain_id)
    if not chain:
        raise HTTPException(404, f"Chain {chain_id} not found")
    return chain.model_dump()
