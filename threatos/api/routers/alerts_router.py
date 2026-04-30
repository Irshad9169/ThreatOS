from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.database import get_db
from threatos.core.dependencies import get_current_user
from threatos.models.user import User
from threatos.services.alert_service import (
    AlertFilters, get_alert_by_id, list_alerts, update_alert_status,
)
from threatos.services.audit_service import Action, Resource, audit

router = APIRouter()

@router.get("")
async def get_alerts(
    status: str | None = Query(None),
    technique_id: str | None = Query(None),
    entity_host: str | None = Query(None),
    min_risk: float = Query(0.0),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    alerts = await list_alerts(db, AlertFilters(
        status=status, technique_id=technique_id,
        entity_host=entity_host, min_risk=min_risk,
        limit=limit, offset=offset))
    return [{"id": str(a.id), "technique_id": a.technique_id,
             "tactic": a.tactic, "severity": a.severity,
             "risk_score": a.risk_score, "status": a.status,
             "entity_host": a.entity_host, "entity_user": a.entity_user,
             "created_at": a.created_at.isoformat()} for a in alerts]

@router.get("/{alert_id}")
async def get_alert(
    alert_id: str,
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    alert = await get_alert_by_id(db, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"id": str(alert.id), "technique_id": alert.technique_id,
            "tactic": alert.tactic, "severity": alert.severity,
            "confidence": alert.confidence, "risk_score": alert.risk_score,
            "entity_host": alert.entity_host, "status": alert.status,
            "created_at": alert.created_at.isoformat()}

@router.put("/{alert_id}/status")
async def set_alert_status(
    alert_id: str, body: dict, request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    old_alert = await get_alert_by_id(db, alert_id)
    if old_alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    old_status = old_alert.status
    new_status = body.get("status","")
    try:
        alert = await update_alert_status(db, alert_id, new_status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    await audit(db, Action.ALERT_STATUS, Resource.ALERT,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=alert_id,
                detail=f"'{current_user.username}' changed alert status: {old_status} → {new_status}",
                changes={"status": {"from": old_status, "to": new_status}},
                request=request)
    return {"id": str(alert.id), "status": alert.status}
