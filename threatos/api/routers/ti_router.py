from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.database import get_db
from threatos.core.dependencies import get_current_user, require_engineer
from threatos.models.user import User
from threatos.services.ti_service import (
    cleanup_expired_enrichments, detect_ioc_type, enrich_alert,
    enrich_ioc, get_enrichment_stats, get_cached_enrichment,
    extract_iocs_from_alert,
)
from threatos.services.alert_service import get_alert_by_id

router = APIRouter()

class EnrichIOCIn(BaseModel):
    ioc_value: str
    ioc_type:  str | None = None   # auto-detected if not provided

class EnrichAlertIn(BaseModel):
    alert_id: str

# ── Single IOC enrichment ─────────────────────────────────────────────────────

@router.post("/enrich")
async def enrich_single_ioc(
    body: EnrichIOCIn,
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Enrich a single IOC (IP, hash, domain) from all available TI sources.
    Results are cached for TI_CACHE_HOURS (default 24h).
    """
    ioc_type = body.ioc_type or detect_ioc_type(body.ioc_value)
    if not ioc_type:
        raise HTTPException(status_code=400,
            detail=f"Cannot detect IOC type for '{body.ioc_value}'. "
                   f"Provide ioc_type: ip, sha256, md5, sha1, or domain.")
    return await enrich_ioc(db, ioc_type, body.ioc_value)

@router.post("/enrich-alert/{alert_id}")
async def enrich_alert_route(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Extract all IOCs from an alert and enrich them.
    Updates the alert's ti_enriched, ti_verdict, ti_summary fields.
    """
    alert = await get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Build alert dict for IOC extraction
    alert_data = {
        "entity_host":  alert.entity_host,
        "entity_user":  alert.entity_user,
        "src_ip":       alert.entity_ip,
        "raw_fields":   alert.raw_match or {},
    }

    result = await enrich_alert(db, alert_data)

    # Update alert with TI verdict
    alert.ti_enriched = True
    alert.ti_verdict  = result["overall_verdict"]
    alert.ti_summary  = result["summary"]
    await db.flush()

    from threatos.services.audit_service import audit, Action, Resource
    await audit(db, Action.TI_ENRICHMENT, Resource.ALERT,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=alert_id,
                detail=f"TI enrichment: {result['iocs_found']} IOCs — "
                       f"verdict={result['overall_verdict']}: {result['summary']}")

    return {
        "alert_id":      alert_id,
        "ti_verdict":    result["overall_verdict"],
        "ti_summary":    result["summary"],
        "iocs_found":    result["iocs_found"],
        "enrichments":   result["enrichments"],
    }

@router.get("/alert/{alert_id}")
async def get_alert_enrichments(
    alert_id: str,
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get cached TI enrichments for an alert."""
    alert = await get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert_data = {
        "entity_host": alert.entity_host,
        "src_ip":      alert.entity_ip,
        "raw_fields":  alert.raw_match or {},
    }

    iocs = extract_iocs_from_alert(alert_data)
    enrichments = []
    for ioc_type, ioc_value in iocs:
        cached = await get_cached_enrichment(db, ioc_type, ioc_value)
        for c in cached:
            enrichments.append({
                "ioc_type":   c.ioc_type,
                "ioc_value":  c.ioc_value,
                "source":     c.source,
                "verdict":    c.verdict,
                "score":      c.score,
                "country":    c.country,
                "asn":        c.asn,
                "tags":       c.tags,
                "enriched_at":c.enriched_at.isoformat(),
            })

    return {
        "alert_id":   alert_id,
        "ti_verdict": alert.ti_verdict,
        "ti_summary": alert.ti_summary,
        "ti_enriched":alert.ti_enriched,
        "enrichments":enrichments,
    }

# ── Bulk enrichment ───────────────────────────────────────────────────────────

@router.post("/enrich-open-alerts")
async def enrich_open_alerts(
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(require_engineer),
    db: AsyncSession = Depends(get_db),
):
    """
    Enrich all open unenriched alerts with TI data.
    Processes up to 'limit' alerts per call.
    Use sparingly — each alert consumes API quota.
    """
    from sqlalchemy import select
    from threatos.models.alert import Alert

    result = await db.execute(
        select(Alert).where(
            Alert.status      == "open",
            Alert.ti_enriched == False,
        ).order_by(Alert.risk_score.desc()).limit(limit)
    )
    alerts  = result.scalars().all()
    results = []

    for alert in alerts:
        alert_data = {
            "entity_host": alert.entity_host,
            "src_ip":      alert.entity_ip,
            "raw_fields":  alert.raw_match or {},
        }
        enrichment = await enrich_alert(db, alert_data)
        alert.ti_enriched = True
        alert.ti_verdict  = enrichment["overall_verdict"]
        alert.ti_summary  = enrichment["summary"]
        results.append({
            "alert_id":  str(alert.id),
            "verdict":   enrichment["overall_verdict"],
            "iocs_found":enrichment["iocs_found"],
            "summary":   enrichment["summary"],
        })

    return {
        "enriched":  len(results),
        "results":   results,
    }

# ── Stats & cache management ──────────────────────────────────────────────────

@router.get("/stats")
async def ti_stats(
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """TI cache statistics and API key status."""
    return await get_enrichment_stats(db)

@router.get("/cache")
async def list_cache(
    verdict:  str | None = Query(None),
    ioc_type: str | None = Query(None),
    limit:    int        = Query(50, ge=1, le=200),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Browse the TI enrichment cache."""
    from sqlalchemy import select
    from threatos.models.ti_enrichment import TIEnrichment
    from datetime import UTC, datetime

    q = select(TIEnrichment).where(
        TIEnrichment.expires_at > datetime.now(UTC))
    if verdict:  q = q.where(TIEnrichment.verdict  == verdict)
    if ioc_type: q = q.where(TIEnrichment.ioc_type == ioc_type)
    q = q.order_by(TIEnrichment.enriched_at.desc()).limit(limit)

    result = await db.execute(q)
    return [{
        "ioc_type":   r.ioc_type,
        "ioc_value":  r.ioc_value,
        "source":     r.source,
        "verdict":    r.verdict,
        "score":      r.score,
        "country":    r.country,
        "asn":        r.asn,
        "tags":       r.tags,
        "enriched_at":r.enriched_at.isoformat(),
        "expires_at": r.expires_at.isoformat(),
    } for r in result.scalars().all()]

@router.delete("/cache/cleanup")
async def cleanup_cache(
    _: User = Depends(require_engineer),
    db: AsyncSession = Depends(get_db),
):
    """Delete expired TI cache entries."""
    deleted = await cleanup_expired_enrichments(db)
    return {"deleted": deleted, "message": f"Removed {deleted} expired entries"}
