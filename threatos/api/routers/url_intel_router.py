from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.database import get_db
from threatos.core.dependencies import get_current_user
from threatos.models.ti_enrichment import TIEnrichment
from threatos.models.user import User
from threatos.services.url_intel_service import (
    URLHAUS_AUTH_KEY, URLSCAN_API_KEY, enrich_url,
)

router = APIRouter()

class InvestigateIn(BaseModel):
    url: str

@router.post("/investigate")
async def investigate_url(
    body: InvestigateIn,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Investigate a URL against VirusTotal, urlscan.io, Spamhaus DBL, and URLhaus.
    Returns combined per-source results plus a plain-text report suitable for
    pasting into an email reply.
    """
    try:
        result = await enrich_url(db, body.url, investigated_by=current_user.username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result

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
        "urlscan_key":    bool(URLSCAN_API_KEY),
        "urlhaus_key":    bool(URLHAUS_AUTH_KEY),
        "spamhaus":       "always available (DNS-based, no key required)",
    }
