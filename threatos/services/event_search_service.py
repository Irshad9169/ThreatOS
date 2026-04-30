from __future__ import annotations
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.models.raw_event import RawEvent

@dataclass
class EventSearchFilters:
    host:        str | None = None
    process:     str | None = None
    command_line:str | None = None
    log_source:  str | None = None
    user:        str | None = None
    hours_back:  int        = 24
    limit:       int        = 200
    offset:      int        = 0

async def search_events(db: AsyncSession,
                        filters: EventSearchFilters) -> list[RawEvent]:
    cutoff = datetime.now(UTC) - timedelta(hours=filters.hours_back)
    q = select(RawEvent).where(RawEvent.received_at >= cutoff)

    if filters.log_source:
        q = q.where(RawEvent.log_source == filters.log_source)
    if filters.host:
        q = q.where(RawEvent.normalized["host"].astext.ilike(f"%{filters.host}%"))
    if filters.process:
        q = q.where(RawEvent.normalized["process"].astext.ilike(f"%{filters.process}%"))
    if filters.command_line:
        q = q.where(RawEvent.normalized["command_line"].astext.ilike(
            f"%{filters.command_line}%"))
    if filters.user:
        q = q.where(RawEvent.normalized["user"].astext.ilike(f"%{filters.user}%"))

    q = q.order_by(RawEvent.received_at.desc()).limit(filters.limit).offset(filters.offset)
    result = await db.execute(q)
    return list(result.scalars().all())

async def get_event_stats(db: AsyncSession, hours_back: int = 24) -> dict:
    from sqlalchemy import func, text
    cutoff = datetime.now(UTC) - timedelta(hours=hours_back)
    result = await db.execute(
        select(
            func.count(RawEvent.id).label("total"),
            func.count(RawEvent.id).filter(
                RawEvent.received_at >= cutoff).label("recent"),
        )
    )
    row = result.one()
    # Per log_source breakdown
    src_result = await db.execute(
        select(RawEvent.log_source, func.count(RawEvent.id).label("cnt"))
        .where(RawEvent.received_at >= cutoff)
        .group_by(RawEvent.log_source)
        .order_by(func.count(RawEvent.id).desc())
    )
    sources = {r.log_source: r.cnt for r in src_result}
    return {
        "total_all_time": int(row.total or 0),
        "last_n_hours":   int(row.recent or 0),
        "hours_back":     hours_back,
        "by_log_source":  sources,
    }
