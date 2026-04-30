from __future__ import annotations
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.database import get_db
from threatos.core.dependencies import get_current_user
from threatos.models.user import User
from threatos.services.event_search_service import (
    EventSearchFilters, get_event_stats, search_events,
)
from threatos.services.suppression_service import get_suppression_stats

router = APIRouter()

@router.get("/search")
async def search_events_route(
    host:         str | None = Query(None),
    process:      str | None = Query(None),
    command_line: str | None = Query(None),
    log_source:   str | None = Query(None),
    user:         str | None = Query(None),
    hours_back:   int        = Query(24, ge=1, le=168),
    limit:        int        = Query(100, ge=1, le=500),
    offset:       int        = Query(0, ge=0),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    events = await search_events(db, EventSearchFilters(
        host=host, process=process, command_line=command_line,
        log_source=log_source, user=user, hours_back=hours_back,
        limit=limit, offset=offset,
    ))
    return [{
        "id":          e.id,
        "received_at": e.received_at.isoformat(),
        "log_source":  e.log_source,
        "hash":        e.hash,
        "normalized":  e.normalized or {},
    } for e in events]

@router.get("/stats")
async def event_stats(
    hours_back: int = Query(24, ge=1, le=168),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await get_event_stats(db, hours_back=hours_back)

@router.get("/suppression-stats")
async def suppression_stats(
    window_minutes: int = Query(15, ge=1, le=1440),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await get_suppression_stats(db, window_minutes=window_minutes)
