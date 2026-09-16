"""
api/routers/rules_router.py
────────────────────────────
Detection rule management routes — thin wrappers only.
Business logic lives in rule_engine.py and rule_ast.py.

Routes:
  GET  /api/rules                list all rules
  GET  /api/rules/{id}           single rule
  POST /api/rules                create a rule
  PUT  /api/rules/{id}/toggle    enable / disable
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from threatos.core.database import get_db
from threatos.detection.rule_engine import load_rules_into_engine
from threatos.models.detection_rule import DetectionRule

router = APIRouter()


# ── Request / Response schemas ────────────────────────────────────────────────

class RuleResponse(BaseModel):
    id:             str
    name:           str
    technique_id:   str
    tactic:         str
    severity:       int
    confidence:     float
    log_sources:    list[str]
    platforms:      list[str]
    tags:           list[str]
    enabled:        bool
    trigger_count:  int
    last_triggered: str | None

    model_config = {"from_attributes": True}


class RuleCreate(BaseModel):
    name:          str   = Field(..., min_length=3, max_length=200)
    technique_id:  str   = Field(..., pattern=r"^T\d{4}(\.\d{3})?$")
    tactic:        str
    severity:      int   = Field(default=5,   ge=1,   le=10)
    confidence:    float = Field(default=0.7, ge=0.0, le=1.0)
    log_sources:   list[str] = Field(default_factory=list)
    platforms:     list[str] = Field(default_factory=list)
    tags:          list[str] = Field(default_factory=list)
    detection_ast: dict[str, Any]
    description:   str | None = None
    author:        str | None = None

    @field_validator("detection_ast")
    @classmethod
    def validate_ast(cls, v: dict) -> dict:
        from threatos.detection.rule_ast import node_from_dict
        try:
            node_from_dict(v)
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError(f"Invalid detection_ast: {exc}") from exc
        return v


# ── Helper ────────────────────────────────────────────────────────────────────

def _to_response(rule: DetectionRule) -> RuleResponse:
    return RuleResponse(
        id=str(rule.id),
        name=rule.name,
        technique_id=rule.technique_id,
        tactic=rule.tactic,
        severity=rule.severity,
        confidence=rule.confidence,
        log_sources=rule.log_sources or [],
        platforms=rule.platforms   or [],
        tags=rule.tags             or [],
        enabled=rule.enabled,
        trigger_count=rule.trigger_count,
        last_triggered=(
            rule.last_triggered.isoformat() if rule.last_triggered else None
        ),
    )


async def _reload_engine(db: AsyncSession) -> int:
    """Reload all enabled rules into the in-memory engine after any mutation."""
    result = await db.execute(
        select(DetectionRule).where(DetectionRule.enabled.is_(True))
    )
    rules = result.scalars().all()
    rows = [
        {
            "id":           str(r.id),
            "name":         r.name,
            "technique_id": r.technique_id,
            "tactic":       r.tactic,
            "log_sources":  r.log_sources or [],
            "severity":     r.severity,
            "confidence":   r.confidence,
            "detection_ast":r.detection_ast,
            "tags":         r.tags or [],
        }
        for r in rules
    ]
    return load_rules_into_engine(rows)


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("", response_model=list[RuleResponse])
async def list_rules(
    enabled_only: bool = True,
    db: AsyncSession = Depends(get_db),
) -> list[RuleResponse]:
    q = select(DetectionRule).order_by(DetectionRule.severity.desc())
    if enabled_only:
        q = q.where(DetectionRule.enabled.is_(True))
    result = await db.execute(q)
    return [_to_response(r) for r in result.scalars().all()]


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> RuleResponse:
    result = await db.execute(
        select(DetectionRule).where(DetectionRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return _to_response(rule)


@router.post("", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    body: RuleCreate,
    db: AsyncSession = Depends(get_db),
) -> RuleResponse:
    """
    Create a detection rule.
    Returns 409 Conflict if a rule with the same name already exists.
    The detection_ast is validated at request time — invalid ASTs return 422.
    """
    rule = DetectionRule(
        name=body.name,
        description=body.description,
        author=body.author,
        technique_id=body.technique_id,
        tactic=body.tactic,
        severity=body.severity,
        confidence=body.confidence,
        log_sources=body.log_sources,
        platforms=body.platforms,
        tags=body.tags,
        detection_ast=body.detection_ast,
        enabled=True,
    )
    db.add(rule)

    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A rule named '{body.name}' already exists.",
        )

    await _reload_engine(db)
    return _to_response(rule)


@router.put("/{rule_id}/toggle")
async def toggle_rule(
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(
        select(DetectionRule).where(DetectionRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    rule.enabled = not rule.enabled
    await _reload_engine(db)
    return {"id": str(rule.id), "enabled": rule.enabled}
