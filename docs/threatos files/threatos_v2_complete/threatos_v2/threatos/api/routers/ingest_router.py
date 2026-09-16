"""
api/routers/ingest_router.py
────────────────────────────
Ingest routes — thin wrappers only.
All business logic lives in threatos.ingestion.normalizer.
Routes do: validate input → call service → persist → return 202.

Routes:
  POST /api/ingest/event      single JSON event
  POST /api/ingest/batch      up to 500 events
  POST /api/ingest/syslog     raw syslog line (text/plain)
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import orjson
from fastapi import APIRouter, Body, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from threatos.core.database import get_db
from threatos.ingestion.normalizer import NormalizedEvent, normalize_event

router = APIRouter()


# ── Request / Response schemas ────────────────────────────────────────────────

class IngestRequest(BaseModel):
    log_source: str = Field(
        ...,
        examples=["json", "winlog", "syslog", "cef"],
        description="Log format identifier",
    )
    payload: dict[str, Any] = Field(
        ...,
        description="Raw log fields as a JSON object",
    )


class IngestResponse(BaseModel):
    status:   str
    event_id: str
    hash:     str | None


class BatchIngestResponse(BaseModel):
    queued:    int
    failed:    int
    event_ids: list[str]


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _persist_event(
    event: NormalizedEvent,
    db: AsyncSession,
) -> None:
    """
    Insert one normalized event into raw_events.
    Uses raw SQL with ON CONFLICT DO NOTHING for deduplication.
    Phase 2 will upgrade this to asyncpg COPY for bulk performance.
    """
    await db.execute(
        text("""
            INSERT INTO raw_events
                (id, received_at, log_source, raw_payload, normalized, hash)
            VALUES
                (:id, :received_at, :log_source, :raw_payload, :normalized, :hash)
            ON CONFLICT DO NOTHING
        """),
        {
            "id":          str(uuid.uuid4()),
            "received_at": datetime.now(UTC),
            "log_source":  event.log_source,
            "raw_payload": orjson.dumps(event.raw_fields).decode(),
            "normalized":  orjson.dumps(event.model_dump(
                exclude={"raw_fields", "event_id"}
            )).decode(),
            "hash":        event.hash,
        },
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post(
    "/event",
    response_model=IngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest a single log event",
)
async def ingest_single_event(
    body: IngestRequest,
    db: AsyncSession = Depends(get_db),
) -> IngestResponse:
    """
    Normalize and persist one log event.
    Returns 202 Accepted immediately — downstream processing is async.
    Returns 400 if the log_source is unsupported.
    """
    try:
        event = normalize_event(
            log_source=body.log_source,
            payload=body.payload,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    await _persist_event(event, db)

    return IngestResponse(
        status="accepted",
        event_id=event.event_id,
        hash=event.hash,
    )


@router.post(
    "/batch",
    response_model=BatchIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest up to 500 events in one request",
)
async def ingest_batch(
    events: list[IngestRequest] = Body(..., max_length=500),
    db: AsyncSession = Depends(get_db),
) -> BatchIngestResponse:
    """
    Normalize and persist a batch of events.
    Each event is processed independently — one failure does not abort the batch.
    """
    queued:    int       = 0
    failed:    int       = 0
    event_ids: list[str] = []

    for req in events:
        try:
            event = normalize_event(
                log_source=req.log_source,
                payload=req.payload,
            )
            await _persist_event(event, db)
            event_ids.append(event.event_id)
            queued += 1
        except Exception:
            failed += 1

    return BatchIngestResponse(
        queued=queued,
        failed=failed,
        event_ids=event_ids,
    )


@router.post(
    "/syslog",
    response_model=IngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest a raw Syslog line (text/plain)",
)
async def ingest_syslog(
    raw_line: str = Body(..., media_type="text/plain"),
    db: AsyncSession = Depends(get_db),
) -> IngestResponse:
    """
    Accept a raw Syslog RFC 5424 / BSD line as plain text.
    Parses it, normalizes, and persists.
    """
    from threatos.ingestion.syslog_parser import parse_syslog

    try:
        parsed = parse_syslog(raw_line)
        event  = normalize_event(log_source="syslog", payload=parsed)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    await _persist_event(event, db)

    return IngestResponse(
        status="accepted",
        event_id=event.event_id,
        hash=event.hash,
    )
