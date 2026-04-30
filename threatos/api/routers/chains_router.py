from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.database import get_db
from threatos.core.dependencies import get_current_user
from threatos.models.user import User
from threatos.services.audit_service import Action, Resource, audit
from threatos.services.chain_service import (
    ChainFilters, correlate_alerts, get_chain_by_id,
    list_chains, update_chain_status,
)

router = APIRouter()

class CorrelateIn(BaseModel):
    host:         str = Field(..., min_length=1)
    window_hours: int = Field(default=24, ge=1, le=168)

def _out(c):
    return {"id": str(c.id), "host": c.host, "tactic_count": c.tactic_count,
            "technique_ids": c.technique_ids or [],
            "tactics_observed": c.tactics_observed or [],
            "alert_ids": c.alert_ids or [], "risk_score": c.risk_score,
            "is_multi_stage": c.is_multi_stage, "status": c.status,
            "first_seen": c.first_seen.isoformat(),
            "last_seen":  c.last_seen.isoformat(),
            "duration_seconds": c.duration_seconds}

@router.post("/correlate")
async def correlate(
    body: CorrelateIn, request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await correlate_alerts(db, body.host, window_hours=body.window_hours)
    await audit(db, Action.CHAIN_CORRELATE, Resource.CHAIN,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role,
                resource_id=result.chain_id if result else None,
                detail=f"'{current_user.username}' correlated host '{body.host}' "
                       f"(window={body.window_hours}h) → "
                       f"{'chain ' + result.chain_id[:8] if result else 'no alerts found'}",
                request=request)
    if result is None:
        return {"message": "No open alerts found for this host in the given window"}
    return {"chain_id": result.chain_id, "host": result.host,
            "alert_count": result.alert_count, "tactic_count": result.tactic_count,
            "is_multi_stage": result.is_multi_stage,
            "risk_score": result.risk_score, "created": result.created}

@router.get("")
async def list_chains_route(
    host:           str | None  = Query(None),
    chain_status:   str | None  = Query(None, alias="status"),
    is_multi_stage: bool | None = Query(None),
    limit:  int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    chains = await list_chains(db, ChainFilters(
        host=host, status=chain_status,
        is_multi_stage=is_multi_stage, limit=limit, offset=offset))
    return [_out(c) for c in chains]

@router.get("/{chain_id}")
async def get_chain(
    chain_id: str,
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    chain = await get_chain_by_id(db, chain_id)
    if chain is None:
        raise HTTPException(status_code=404, detail="Chain not found")
    return _out(chain)

@router.put("/{chain_id}/status")
async def update_status(
    chain_id: str, body: dict, request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    chain = await get_chain_by_id(db, chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")
    old_status = chain.status
    new_status = body.get("status","")
    try:
        chain = await update_chain_status(db, chain_id, new_status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    await audit(db, Action.CHAIN_STATUS, Resource.CHAIN,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=chain_id,
                detail=f"'{current_user.username}' changed chain status: {old_status} → {new_status}",
                changes={"status": {"from": old_status, "to": new_status}},
                request=request)
    return _out(chain)
