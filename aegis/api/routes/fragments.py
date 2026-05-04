"""Attack Fragment API routes."""

from fastapi import APIRouter, HTTPException, Query

router = APIRouter(prefix="/fragments", tags=["fragments"])


def _get_store():
    from aegis.api.server import get_fragments_store
    return get_fragments_store()


@router.get("")
def list_fragments(limit: int = Query(50, ge=1, le=500)):
    store = _get_store()
    items = sorted(store.values(), key=lambda f: f.timestamp_span[1] if hasattr(f, 'timestamp_span') else "", reverse=True)
    return [f.model_dump() for f in items[:limit]]


@router.get("/{fragment_id}")
def get_fragment(fragment_id: str):
    store = _get_store()
    frag = store.get(fragment_id)
    if not frag:
        raise HTTPException(404, f"Fragment {fragment_id} not found")
    return frag.model_dump()
