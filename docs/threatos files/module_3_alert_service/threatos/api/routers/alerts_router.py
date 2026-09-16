"""
api/routers/alerts_router.py
─────────────────────────────
Alert management routes — thin wrappers over alert_service.py.
Zero business logic here. Routes only: validate → call service → return.

Routes:
  GET  /api/alerts             filtered list
  GET  /api/alerts/{id}        single alert
  PUT  /api/alerts/{id}/status update status
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from threatos.core.database import get_db
from threatos.models.alert import VALID_STATUSES, Alert
from threatos.services.alert_service import (
    AlertFilters,
    get_alert_by_id,
    list_alerts,
    update_alert_status,
)

router = APIRouter()


# ── Response schema ───────────────────────────────────────────────────────────

class AlertResponse(BaseModel):
    id:               str
    rule_id:          str | None
    rule_name:        str | None
    technique_id:     str
    tactic:           str
    severity:         int
    confidence:       float
    asset_criticality:int
    risk_score:       float
    entity_host:      str | None
    entity_user:      str | None
    entity_process:   str | None
    entity_ip:        str | None
    status:           str
    description:      str | None
    created_at:       str
    updated_at:       str
    closed_at:        str | None

    model_config = {"from_attributes": True}


class StatusUpdateRequest(BaseModel):
    status: str = Field(
        ...,
        description=f"Must be one of: {VALID_STATUSES}",
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _to_response(alert: Alert) -> AlertResponse:
    return AlertResponse(
        id=str(alert.id),
        rule_id=alert.rule_id,
        rule_name=alert.rule_name,
        technique_id=alert.technique_id,
        tactic=alert.tactic,
        severity=alert.severity,
        confidence=alert.confidence,
        asset_criticality=alert.asset_criticality,
        risk_score=alert.risk_score,
        entity_host=alert.entity_host,
        entity_user=alert.entity_user,
        entity_process=alert.entity_process,
        entity_ip=alert.entity_ip,
        status=alert.status,
        description=alert.description,
        created_at=alert.created_at.isoformat(),
        updated_at=alert.updated_at.isoformat(),
        closed_at=alert.closed_at.isoformat() if alert.closed_at else None,
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get(
    "",
    response_model=list[AlertResponse],
    summary="List alerts with optional filters",
)
async def list_alerts_route(
    status:       str | None  = Query(None),
    technique_id: str | None  = Query(None),
    tactic:       str | None  = Query(None),
    entity_host:  str | None  = Query(None),
    min_score:    float       = Query(0.0, ge=0, le=100),
    limit:        int         = Query(50, ge=1, le=500),
    offset:       int         = Query(0,  ge=0),
    db: AsyncSession          = Depends(get_db),
) -> list[AlertResponse]:
    """
    Returns alerts ordered by risk_score descending.
    All query params are optional — omit to return all alerts.
    """
    filters = AlertFilters(
        status=status,
        technique_id=technique_id,
        tactic=tactic,
        entity_host=entity_host,
        min_score=min_score,
        limit=limit,
        offset=offset,
    )
    alerts = await list_alerts(db, filters)
    return [_to_response(a) for a in alerts]


@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Get a single alert by ID",
)
async def get_alert_route(
    alert_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> AlertResponse:
    alert = await get_alert_by_id(db, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _to_response(alert)


@router.put(
    "/{alert_id}/status",
    response_model=AlertResponse,
    summary="Update an alert's status",
)
async def update_status_route(
    alert_id: uuid.UUID,
    body: StatusUpdateRequest,
    db: AsyncSession = Depends(get_db),
) -> AlertResponse:
    """
    Update alert status. Returns 400 for invalid status values.
    Returns 404 if the alert does not exist.
    """
    try:
        updated = await update_alert_status(db, alert_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if updated is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    return _to_response(updated)
