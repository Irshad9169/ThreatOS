"""
api/routers/purple_router.py
──────────────────────────────
Purple team and risk scoring routes.

Routes:
  POST /api/purple/validate         validate a single technique
  POST /api/purple/validate-chain   validate all techniques in a chain
  GET  /api/purple/runs             list historical runs
  POST /api/purple/score            compute v2 risk score
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Any

from threatos.core.database import get_db
from threatos.detection.risk_scorer import compute_score_v2
from threatos.models.purple_team_run import PurpleTeamRun
from threatos.services.purple_service import (
    list_purple_runs,
    run_chain_validation,
    run_purple_validation,
)

router = APIRouter()


# ── Schemas ───────────────────────────────────────────────────────────────────

class ValidateRequest(BaseModel):
    technique_id:   str
    emulated_event: dict[str, Any] = Field(default_factory=dict)
    chain_id:       str | None = None
    run_by:         str | None = None
    notes:          str | None = None


class ValidateChainRequest(BaseModel):
    chain_id:       str
    technique_ids:  list[str]
    emulated_events:dict[str, dict[str, Any]] = Field(default_factory=dict)
    run_by:         str | None = None


class ScoreV2Request(BaseModel):
    severity:           int   = Field(..., ge=1, le=10)
    confidence:         float = Field(..., ge=0.0, le=1.0)
    asset_criticality:  int   = Field(default=2, ge=1, le=4)
    chain_tactic_count: int   = Field(default=1, ge=1)
    is_multi_stage:     bool  = False


class RunResponse(BaseModel):
    id:             str
    technique_id:   str
    chain_id:       str | None
    detection_rate: float
    verdict:        str
    rules_expected: list[str]
    rules_fired:    list[str]
    rules_missed:   list[str]
    run_by:         str | None
    run_at:         str


def _run_to_response(run: PurpleTeamRun) -> RunResponse:
    return RunResponse(
        id=run.id,
        technique_id=run.technique_id,
        chain_id=run.chain_id,
        detection_rate=run.detection_rate,
        verdict=run.verdict,
        rules_expected=run.rules_expected or [],
        rules_fired=run.rules_fired or [],
        rules_missed=run.rules_missed or [],
        run_by=run.run_by,
        run_at=run.run_at.isoformat(),
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/validate")
async def validate_technique(
    body: ValidateRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await run_purple_validation(
        db, body.technique_id, body.emulated_event,
        chain_id=body.chain_id, run_by=body.run_by, notes=body.notes,
    )
    return {
        "run_id":         result.run_id,
        "technique_id":   result.technique_id,
        "verdict":        result.verdict,
        "detection_rate": result.detection_rate,
        "rules_expected": result.rules_expected,
        "rules_fired":    result.rules_fired,
        "rules_missed":   result.rules_missed,
    }


@router.post("/validate-chain")
async def validate_chain(
    body: ValidateChainRequest,
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    results = await run_chain_validation(
        db,
        chain_id=body.chain_id,
        technique_ids=body.technique_ids,
        emulated_events=body.emulated_events,
        run_by=body.run_by,
    )
    return [
        {
            "run_id":         r.run_id,
            "technique_id":   r.technique_id,
            "verdict":        r.verdict,
            "detection_rate": r.detection_rate,
            "rules_fired":    r.rules_fired,
            "rules_missed":   r.rules_missed,
        }
        for r in results
    ]


@router.get("/runs", response_model=list[RunResponse])
async def get_runs(
    technique_id: str | None = Query(None),
    chain_id:     str | None = Query(None),
    limit:        int        = Query(50, ge=1, le=500),
    offset:       int        = Query(0, ge=0),
    db: AsyncSession          = Depends(get_db),
) -> list[RunResponse]:
    runs = await list_purple_runs(db, technique_id=technique_id,
                                   chain_id=chain_id, limit=limit, offset=offset)
    return [_run_to_response(r) for r in runs]


@router.post("/score")
async def score_v2(body: ScoreV2Request) -> dict:
    """Compute a v2 chain-aware risk score. No DB required."""
    components = compute_score_v2(
        severity=body.severity,
        confidence=body.confidence,
        asset_criticality=body.asset_criticality,
        chain_tactic_count=body.chain_tactic_count,
        is_multi_stage=body.is_multi_stage,
    )
    return components.as_dict()
