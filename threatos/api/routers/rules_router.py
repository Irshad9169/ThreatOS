from __future__ import annotations
import uuid
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.database import get_db
from threatos.core.dependencies import get_current_user, require_engineer
from threatos.models.detection_rule import DetectionRule
from threatos.models.user import User
from threatos.services.audit_service import Action, Resource, audit

router = APIRouter()

class RuleIn(BaseModel):
    name: str; technique_id: str; tactic: str
    detection_ast: dict
    severity:   int   = Field(default=5, ge=1, le=10)
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    log_sources: list[str] = []; platforms: list[str] = []
    tags: list[str] = []; enabled: bool = True
    description: str | None = None; author: str | None = None

def _out(r: DetectionRule) -> dict:
    return {"id": str(r.id), "name": r.name, "technique_id": r.technique_id,
            "tactic": r.tactic, "severity": r.severity, "confidence": r.confidence,
            "enabled": r.enabled, "trigger_count": r.trigger_count,
            "description": r.description, "author": r.author,
            "log_sources": r.log_sources or [], "tags": r.tags or []}

@router.get("")
async def list_rules(
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(DetectionRule).order_by(DetectionRule.name))
    return [_out(r) for r in result.scalars().all()]

@router.post("", status_code=201)
async def create_rule(
    body: RuleIn, request: Request,
    current_user: User = Depends(require_engineer),
    db: AsyncSession = Depends(get_db),
):
    rule = DetectionRule(
        id=str(uuid.uuid4()), name=body.name,
        technique_id=body.technique_id, tactic=body.tactic,
        detection_ast=body.detection_ast, severity=body.severity,
        confidence=body.confidence, log_sources=body.log_sources,
        platforms=body.platforms, tags=body.tags, enabled=body.enabled,
        description=body.description, author=body.author, trigger_count=0,
    )
    db.add(rule)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail=f"Rule '{body.name}' already exists")
    await audit(db, Action.RULE_CREATE, Resource.RULE,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=str(rule.id),
                detail=f"Created rule '{rule.name}' for {rule.technique_id}",
                changes={"name": rule.name, "technique_id": rule.technique_id,
                         "severity": rule.severity, "enabled": rule.enabled},
                request=request)
    return {"id": str(rule.id), "name": rule.name}

@router.put("/{rule_id}/toggle")
async def toggle_rule(
    rule_id: str, request: Request,
    current_user: User = Depends(require_engineer),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule   = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    old_state   = rule.enabled
    rule.enabled = not rule.enabled
    await db.flush()
    await audit(db, Action.RULE_TOGGLE, Resource.RULE,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=rule_id,
                detail=f"'{current_user.username}' {'enabled' if rule.enabled else 'disabled'} rule '{rule.name}'",
                changes={"enabled": {"from": old_state, "to": rule.enabled}},
                request=request)
    return {"id": str(rule.id), "enabled": rule.enabled}
