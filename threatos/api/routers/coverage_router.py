from __future__ import annotations
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.attck_kb import get_cache_size, load_attck_bundle
from threatos.core.database import get_db
from threatos.core.dependencies import get_current_user, require_engineer
from threatos.core.settings import settings
from threatos.models.user import User
from threatos.services.audit_service import Action, Resource, audit
from threatos.services.coverage_service import (
    get_coverage, get_coverage_summary, refresh_coverage,
)

router = APIRouter()

async def _ensure_attck_loaded():
    if get_cache_size() == 0:
        try:
            await load_attck_bundle(settings.attck_bundle_url)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("ATT&CK bundle load failed: %s", exc)

@router.post("/refresh")
async def trigger_refresh(
    request: Request,
    current_user: User = Depends(require_engineer),
    db: AsyncSession = Depends(get_db),
):
    await _ensure_attck_loaded()
    summary = await refresh_coverage(db)
    await audit(db, Action.COVERAGE_REFRESH, Resource.COVERAGE,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role,
                detail=f"'{current_user.username}' refreshed ATT&CK coverage — "
                       f"{summary.covered}/{summary.total_techniques} techniques ({summary.coverage_pct}%)",
                request=request)
    return {"total_techniques": summary.total_techniques, "covered": summary.covered,
            "gaps": summary.gaps, "coverage_pct": summary.coverage_pct}

@router.get("")
async def get_coverage_matrix(
    tactic:       str | None = Query(None),
    covered_only: bool       = Query(False),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    rows = await get_coverage(db, tactic=tactic, covered_only=covered_only)
    return [{"technique_id": r.technique_id, "technique_name": r.technique_name,
             "tactic": r.tactic, "rule_count": r.rule_count,
             "confidence_avg": round(r.confidence_avg, 4),
             "covered": r.covered, "platforms": r.platforms,
             "priority_gap": r.priority_gap} for r in rows]

@router.get("/summary")
async def get_summary(
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    s = await get_coverage_summary(db)
    return {"total_techniques": s.total_techniques, "covered": s.covered,
            "gaps": s.gaps, "coverage_pct": s.coverage_pct}
