"""
api/routers/coverage_router.py
────────────────────────────────
Coverage routes — thin wrappers over coverage_service.py.

Routes:
  POST /api/coverage/refresh    recompute matrix from current rules
  GET  /api/coverage            query current matrix
  GET  /api/coverage/summary    aggregate stats only
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from threatos.core.database import get_db
from threatos.services.coverage_service import (
    CoverageRow,
    CoverageSummary,
    get_coverage,
    get_coverage_summary,
    refresh_coverage,
)

router = APIRouter()


# ── Response schemas ──────────────────────────────────────────────────────────

class CoverageRowResponse(BaseModel):
    technique_id:   str
    technique_name: str | None
    tactic:         str | None
    rule_count:     int
    confidence_avg: float
    covered:        bool
    last_triggered: str | None
    platforms:      list[str]
    priority_gap:   bool


class CoverageSummaryResponse(BaseModel):
    total_techniques: int
    covered:          int
    gaps:             int
    coverage_pct:     float


def _row_to_response(row: CoverageRow) -> CoverageRowResponse:
    return CoverageRowResponse(
        technique_id=row.technique_id,
        technique_name=row.technique_name,
        tactic=row.tactic,
        rule_count=row.rule_count,
        confidence_avg=round(row.confidence_avg, 4),
        covered=row.covered,
        last_triggered=(
            row.last_triggered.isoformat() if row.last_triggered else None
        ),
        platforms=row.platforms,
        priority_gap=row.priority_gap,
    )


def _summary_to_response(s: CoverageSummary) -> CoverageSummaryResponse:
    return CoverageSummaryResponse(
        total_techniques=s.total_techniques,
        covered=s.covered,
        gaps=s.gaps,
        coverage_pct=s.coverage_pct,
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post(
    "/refresh",
    response_model=CoverageSummaryResponse,
    summary="Recompute the ATT&CK coverage matrix",
)
async def trigger_refresh(
    db: AsyncSession = Depends(get_db),
) -> CoverageSummaryResponse:
    """
    Recompute the full coverage matrix from current detection rules
    and the ATT&CK knowledge base. Returns updated summary stats.
    Idempotent — safe to call multiple times.
    """
    summary = await refresh_coverage(db)
    return _summary_to_response(summary)


@router.get(
    "",
    response_model=list[CoverageRowResponse],
    summary="Get the current ATT&CK coverage matrix",
)
async def get_coverage_matrix(
    tactic:       str | None = Query(None, description="Filter by tactic shortname"),
    covered_only: bool       = Query(False, description="Return only covered techniques"),
    db: AsyncSession          = Depends(get_db),
) -> list[CoverageRowResponse]:
    """
    Returns the current coverage matrix ordered by kill-chain tactic then technique ID.
    Returns an empty list if refresh has never been called.
    """
    rows = await get_coverage(db, tactic=tactic, covered_only=covered_only)
    return [_row_to_response(r) for r in rows]


@router.get(
    "/summary",
    response_model=CoverageSummaryResponse,
    summary="Get coverage aggregate stats",
)
async def get_summary(
    db: AsyncSession = Depends(get_db),
) -> CoverageSummaryResponse:
    """Fast aggregate stats — does not trigger a full refresh."""
    summary = await get_coverage_summary(db)
    return _summary_to_response(summary)
