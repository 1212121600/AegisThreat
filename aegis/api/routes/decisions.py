"""Decision Script API routes."""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/decisions", tags=["decisions"])


class DecisionApproval(BaseModel):
    approved: bool = Field(..., description="Approve or reject the decision")
    approved_by: str = Field(..., description="Name/ID of the human approver")
    comment: str = ""


def _get_store():
    from aegis.api.server import get_decisions_store, get_store
    return get_decisions_store(), get_store()


@router.get("")
def list_decisions(limit: int = Query(50, ge=1, le=500)):
    store, _ = _get_store()
    items = sorted(store.values(), key=lambda d: d.created_at, reverse=True)
    return [d.model_dump() for d in items[:limit]]


@router.get("/{decision_id}")
def get_decision(decision_id: str):
    store, _ = _get_store()
    dec = store.get(decision_id)
    if not dec:
        raise HTTPException(404, f"Decision {decision_id} not found")
    return dec.model_dump()


@router.post("/{decision_id}/approve")
def approve_decision(decision_id: str, approval: DecisionApproval):
    import logging
    logger = logging.getLogger(__name__)
    store, db = _get_store()
    dec = store.get(decision_id)
    if not dec:
        raise HTTPException(404, f"Decision {decision_id} not found")

    if approval.approved:
        dec.requires_human_approval = False
        dec.approved_by = approval.approved_by
        if db:
            db.approve_decision(decision_id, approval.approved_by)
            db.audit("human", "decision_approved", {
                "decision_id": decision_id,
                "approved_by": approval.approved_by,
                "comment": approval.comment,
            })
        logger.info("Decision %s APPROVED by %s", decision_id, approval.approved_by)
    else:
        logger.info("Decision %s REJECTED by %s", decision_id, approval.approved_by)

    return {
        "decision_id": decision_id,
        "approved": approval.approved,
        "approved_by": approval.approved_by,
    }
