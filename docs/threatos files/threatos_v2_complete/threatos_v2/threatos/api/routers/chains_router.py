"""
api/routers/chains_router.py
──────────────────────────────
Attack chain routes — thin wrappers over chain_service.py.

Routes:
  POST /api/chains/correlate    run correlation for a host
  GET  /api/chains              filtered list
  GET  /api/chains/{id}         single chain detail
  PUT  /api/chains/{id}/status  update status
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from threatos.core.database import get_db
from threatos.models.attack_chain import CHAIN_STATUSES, AttackChain
from threatos.services.chain_service import (
    ChainFilters,
    correlate_alerts,
    get_chain_by_id,
    list_chains,
    update_chain_status,
)

router = APIRouter()


# ── Schemas ───────────────────────────────────────────────────────────────────

class ChainResponse(BaseModel):
    id:               str
    host:             str
    tactic_count:     int
    technique_ids:    list[str]
    tactics_observed: list[str]
    alert_ids:        list[str]
    risk_score:       float
    is_multi_stage:   bool
    status:           str
    first_seen:       str
    last_seen:        str
    duration_seconds: int


class CorrelateRequest(BaseModel):
    host:         str   = Field(..., min_length=1)
    window_hours: int   = Field(default=24, ge=1, le=168)


class StatusUpdateRequest(BaseModel):
    status: str = Field(..., description=f"One of: {CHAIN_STATUSES}")


def _to_response(chain: AttackChain) -> ChainResponse:
    return ChainResponse(
        id=str(chain.id),
        host=chain.host,
        tactic_count=chain.tactic_count,
        technique_ids=chain.technique_ids or [],
        tactics_observed=chain.tactics_observed or [],
        alert_ids=chain.alert_ids or [],
        risk_score=chain.risk_score,
        is_multi_stage=chain.is_multi_stage,
        status=chain.status,
        first_seen=chain.first_seen.isoformat(),
        last_seen=chain.last_seen.isoformat(),
        duration_seconds=chain.duration_seconds,
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post(
    "/correlate",
    status_code=status.HTTP_200_OK,
    summary="Correlate alerts for a host into an attack chain",
)
async def correlate_route(
    body: CorrelateRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Run correlation for a single host.
    Returns a summary dict.
    Returns 204 if no open alerts exist within the window.
    """
    result = await correlate_alerts(db, body.host, window_hours=body.window_hours)
    if result is None:
        return {"message": "No open alerts found for this host in the given window"}
    return {
        "chain_id":      result.chain_id,
        "host":          result.host,
        "alert_count":   result.alert_count,
        "tactic_count":  result.tactic_count,
        "is_multi_stage":result.is_multi_stage,
        "risk_score":    result.risk_score,
        "created":       result.created,
    }


@router.get(
    "",
    response_model=list[ChainResponse],
    summary="List attack chains",
)
async def list_chains_route(
    host:          str | None  = Query(None),
    chain_status:  str | None  = Query(None, alias="status"),
    is_multi_stage:bool | None = Query(None),
    min_tactics:   int         = Query(1, ge=1),
    limit:         int         = Query(50, ge=1, le=500),
    offset:        int         = Query(0,  ge=0),
    db: AsyncSession            = Depends(get_db),
) -> list[ChainResponse]:
    chains = await list_chains(db, ChainFilters(
        host=host,
        status=chain_status,
        is_multi_stage=is_multi_stage,
        min_tactic_count=min_tactics,
        limit=limit,
        offset=offset,
    ))
    return [_to_response(c) for c in chains]


@router.get(
    "/{chain_id}",
    response_model=ChainResponse,
    summary="Get a single attack chain",
)
async def get_chain_route(
    chain_id: str,
    db: AsyncSession = Depends(get_db),
) -> ChainResponse:
    chain = await get_chain_by_id(db, chain_id)
    if chain is None:
        raise HTTPException(status_code=404, detail="Chain not found")
    return _to_response(chain)


@router.put(
    "/{chain_id}/status",
    response_model=ChainResponse,
    summary="Update an attack chain's status",
)
async def update_status_route(
    chain_id: str,
    body: StatusUpdateRequest,
    db: AsyncSession = Depends(get_db),
) -> ChainResponse:
    try:
        chain = await update_chain_status(db, chain_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if chain is None:
        raise HTTPException(status_code=404, detail="Chain not found")
    return _to_response(chain)
