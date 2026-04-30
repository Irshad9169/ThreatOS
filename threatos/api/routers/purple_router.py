from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.database import get_db
from threatos.core.dependencies import get_current_user
from threatos.detection.risk_scorer import compute_score_v2
from threatos.models.user import User
from threatos.services.audit_service import Action, Resource, audit
from threatos.services.purple_service import (
    list_purple_runs, run_chain_validation, run_purple_validation,
)

router = APIRouter()

class ValidateIn(BaseModel):
    technique_id:   str
    emulated_event: dict[str, Any] = {}
    chain_id:       str | None     = None
    run_by:         str | None     = None

class ValidateChainIn(BaseModel):
    chain_id:        str
    technique_ids:   list[str]
    emulated_events: dict[str, dict[str, Any]] = {}
    run_by:          str | None = None

class ScoreIn(BaseModel):
    severity:          int   = Field(..., ge=1, le=10)
    confidence:        float = Field(..., ge=0.0, le=1.0)
    asset_criticality: int   = Field(default=2, ge=1, le=4)
    chain_tactic_count:int   = Field(default=1, ge=1)
    is_multi_stage:    bool  = False

@router.post("/validate")
async def validate_technique(
    body: ValidateIn, request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    r = await run_purple_validation(db, body.technique_id, body.emulated_event,
                                     chain_id=body.chain_id, run_by=body.run_by)
    await audit(db, Action.PURPLE_VALIDATE, Resource.PURPLE,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=r.run_id,
                detail=f"'{current_user.username}' validated {body.technique_id} — "
                       f"verdict={r.verdict} detection={r.detection_rate}%",
                request=request)
    return {"run_id": r.run_id, "technique_id": r.technique_id,
            "verdict": r.verdict, "detection_rate": r.detection_rate,
            "rules_expected": r.rules_expected, "rules_fired": r.rules_fired,
            "rules_missed": r.rules_missed}

@router.post("/validate-chain")
async def validate_chain(
    body: ValidateChainIn, request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    results = await run_chain_validation(db, body.chain_id, body.technique_ids,
                                          body.emulated_events, run_by=body.run_by)
    await audit(db, Action.PURPLE_VALIDATE, Resource.PURPLE,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=body.chain_id,
                detail=f"'{current_user.username}' validated chain {body.chain_id[:8]} "
                       f"({len(body.technique_ids)} techniques)",
                request=request)
    return [{"run_id": r.run_id, "technique_id": r.technique_id,
             "verdict": r.verdict, "detection_rate": r.detection_rate,
             "rules_fired": r.rules_fired, "rules_missed": r.rules_missed}
            for r in results]

@router.get("/runs")
async def get_runs(
    technique_id: str | None = Query(None),
    chain_id:     str | None = Query(None),
    limit:  int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    runs = await list_purple_runs(db, technique_id=technique_id,
                                   chain_id=chain_id, limit=limit, offset=offset)
    return [{"id": r.id, "technique_id": r.technique_id, "verdict": r.verdict,
             "detection_rate": r.detection_rate,
             "run_at": r.run_at.isoformat()} for r in runs]

@router.post("/score")
async def score_v2(body: ScoreIn, _: User = Depends(get_current_user)):
    c = compute_score_v2(body.severity, body.confidence, body.asset_criticality,
                          body.chain_tactic_count, body.is_multi_stage)
    return c.as_dict()
