from __future__ import annotations
from datetime import UTC, datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.database import get_db
from threatos.core.dependencies import get_current_user, require_ingest
from threatos.core.sanitiser import (
    MAX_BATCH_SIZE, check_payload_size,
    sanitise_payload, validate_log_source,
)
from threatos.ingestion.normalizer import normalize_event
from threatos.models.raw_event import RawEvent
from threatos.models.user import User
from threatos.services.audit_service import Action, Resource, audit

router = APIRouter()

class EventIn(BaseModel):
    payload: dict
    fmt:     str = "json"

@router.post("/event", status_code=201)
async def ingest_event(
    body: EventIn,
    request: Request,
    current_user: User = Depends(require_ingest),
    db: AsyncSession = Depends(get_db),
):
    # Size check
    ok, err = check_payload_size(body.payload)
    if not ok:
        raise HTTPException(status_code=413, detail=err)

    # Sanitise
    clean_payload = sanitise_payload(body.payload)
    clean_fmt     = validate_log_source(body.fmt)

    ev = normalize_event(clean_payload, clean_fmt)

    # Dedup check
    if ev.hash:
        exists = await db.execute(
            select(RawEvent).where(RawEvent.hash == ev.hash))
        if exists.scalar_one_or_none():
            return {"status": "duplicate", "hash": ev.hash}

    raw = RawEvent(
        received_at=datetime.now(UTC), log_source=ev.log_source,
        raw_payload=clean_payload, normalized=ev.to_flat_dict(),
        hash=ev.hash,
    )
    db.add(raw)

    await audit(db, Action.EVENT_INGEST, Resource.INGEST,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role,
                detail=f"Event ingested: source={ev.log_source} host={ev.host}",
                request=request)

    return {"status": "accepted", "event_id": ev.event_id, "hash": ev.hash}

@router.post("/batch", status_code=201)
async def ingest_batch(
    events: list[EventIn],
    request: Request,
    current_user: User = Depends(require_ingest),
    db: AsyncSession = Depends(get_db),
):
    if len(events) > MAX_BATCH_SIZE:
        raise HTTPException(status_code=400,
            detail=f"Batch too large: {len(events)} events (max {MAX_BATCH_SIZE})")

    accepted = 0; duplicates = 0; rejected = 0

    for body in events:
        ok, err = check_payload_size(body.payload)
        if not ok:
            rejected += 1
            continue

        clean_payload = sanitise_payload(body.payload)
        clean_fmt     = validate_log_source(body.fmt)

        ev = normalize_event(clean_payload, clean_fmt)

        if ev.hash:
            exists = await db.execute(
                select(RawEvent).where(RawEvent.hash == ev.hash))
            if exists.scalar_one_or_none():
                duplicates += 1
                continue

        raw = RawEvent(
            received_at=datetime.now(UTC), log_source=ev.log_source,
            raw_payload=clean_payload, normalized=ev.to_flat_dict(),
            hash=ev.hash,
        )
        db.add(raw)
        accepted += 1

    await audit(db, Action.BATCH_INGEST, Resource.INGEST,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role,
                detail=f"Batch ingest: {accepted} accepted / "
                       f"{duplicates} duplicates / {rejected} rejected",
                request=request)

    return {"accepted": accepted, "duplicates": duplicates, "rejected": rejected}

@router.post("/syslog", status_code=201)
async def ingest_syslog(
    body: dict,
    current_user: User = Depends(require_ingest),
    db: AsyncSession = Depends(get_db),
):
    ok, err = check_payload_size(body)
    if not ok:
        raise HTTPException(status_code=413, detail=err)

    clean_body = sanitise_payload(body)
    ev = normalize_event(clean_body, "syslog")
    raw = RawEvent(
        received_at=datetime.now(UTC), log_source="syslog",
        raw_payload=clean_body, normalized=ev.to_flat_dict(), hash=ev.hash,
    )
    db.add(raw)
    return {"status": "accepted", "event_id": ev.event_id}
