from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.database import get_db
from threatos.core.dependencies import get_current_user
from threatos.models.ti_enrichment import TIEnrichment
from threatos.models.user import User
from threatos.services.audit_service import Action, Resource, audit
from threatos.services.url_intel_service import (
    enrich_url, get_investigation, get_key_status, list_investigations,
)

router = APIRouter()

class InvestigateIn(BaseModel):
    url: str

@router.post("/investigate")
async def investigate_url(
    body: InvestigateIn, request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Investigate a URL against VirusTotal, urlscan.io, Spamhaus DBL, SURBL,
    URLhaus, RDAP domain age, Google Safe Browsing, and PhishTank. Returns
    combined per-source results plus a plain-text report suitable for
    pasting into an email reply.
    """
    try:
        result = await enrich_url(db, body.url, investigated_by=current_user.username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    await audit(db, Action.URL_INVESTIGATE, Resource.URL_INTEL,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=result["id"],
                detail=f"'{current_user.username}' investigated {result['domain']} — "
                       f"verdict={result['overall_verdict']}",
                request=request)

    return result

@router.get("/history")
async def investigation_history(
    limit: int = Query(50, ge=1, le=200),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Past investigations, most recent first. Includes the full report_text
    so a past report can be re-viewed without re-scanning."""
    records = await list_investigations(db, limit=limit)
    return [{
        "id": r.id, "url": r.url, "domain": r.domain,
        "overall_verdict": r.overall_verdict, "report_text": r.report_text,
        "investigated_by": r.investigated_by,
        "investigated_at": r.investigated_at.isoformat(),
    } for r in records]

@router.get("/history/{investigation_id}")
async def investigation_detail(
    investigation_id: str,
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    record = await get_investigation(db, investigation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return {
        "id": record.id, "url": record.url, "domain": record.domain,
        "overall_verdict": record.overall_verdict, "report_text": record.report_text,
        "investigated_by": record.investigated_by,
        "investigated_at": record.investigated_at.isoformat(),
    }

@router.get("/stats")
async def url_intel_stats(
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """URL-intel cache stats and which optional API keys are configured."""
    url_sources = ("virustotal", "urlscan", "urlhaus")
    total = await db.execute(
        select(func.count(TIEnrichment.id)).where(
            TIEnrichment.ioc_type == "url",
            TIEnrichment.source.in_(url_sources),
        )
    )
    spamhaus_total = await db.execute(
        select(func.count(TIEnrichment.id)).where(TIEnrichment.source == "spamhaus")
    )
    return {
        "total_cached":   int(total.scalar() or 0) + int(spamhaus_total.scalar() or 0),
        **get_key_status(),
        "spamhaus":       "always available (DNS-based, no key required)",
    }
