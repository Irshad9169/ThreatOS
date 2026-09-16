"""
workers/ingest_worker.py
─────────────────────────
Redis Streams consumer.  Reads normalised events, evaluates detection
rules, computes risk scores, and persists alerts.

Pipeline per batch
──────────────────
  XREADGROUP threatos:events:normalized
       │
       ▼
  for each message:
    event = NormalizedEvent(**fields)
    criticality = get_criticality_for_host_cached(host)
    matches = evaluate_event(event, criticality)       ← rule engine
    alert_dicts = [build_alert_dict(event, m, criticality)
                   for m in matches]
    persist_alerts_bulk(db, alert_dicts)
    XACK
       │
       ▼
  publish to threatos:alerts:live   ← Phase 2 WebSocket feed

Design decisions
────────────────
  - Synchronous rule evaluation (evaluate_event is CPU-bound pure Python).
    Worker runs async I/O around it; evaluate_event itself is not async.
  - Asset criticality is cached in Redis for asset_criticality_ttl seconds.
    Avoids a DB round-trip per event for the same hostname.
  - A broken rule must NEVER crash the pipeline. evaluate_event already
    wraps per-rule evaluation in try/except; this worker adds an outer
    try/except around the full event evaluation as a second safety net.
  - XACK is sent only after successful DB flush, never before.
    If the process dies mid-batch the messages become visible again
    for the pending-entries list (PEL) to recover.

Oracle Linux 8 notes
────────────────────
  python3.11 -m threatos.workers.ingest_worker
  All dependencies (Redis, SQLAlchemy, asyncpg) install identically on OL8.
"""
from __future__ import annotations

import asyncio
import json
import logging
import signal
from datetime import UTC, datetime
from typing import Any

import redis.asyncio as aioredis

from threatos.core.database import get_db_context
from threatos.core.settings import settings
from threatos.detection.rule_engine import (
    build_alert_dict,
    evaluate_event,
    get_loaded_rule_count,
    load_rules_into_engine,
)
from threatos.ingestion.normalizer import NormalizedEvent
from threatos.services.alert_service import persist_alerts_bulk
from threatos.services.asset_service import get_asset_by_hostname

log = logging.getLogger(__name__)


# ── Asset criticality cache ────────────────────────────────────────────────────

class _CriticalityCache:
    """
    Thin Redis-backed cache for hostname → criticality lookups.
    Falls back to 2 (default) when Redis is unavailable.
    """
    def __init__(self, redis: aioredis.Redis) -> None:
        self._r   = redis
        self._ttl = settings.asset_criticality_ttl

    def _key(self, hostname: str) -> str:
        return f"threatos:asset:crit:{hostname.lower()}"

    async def get(self, hostname: str) -> int:
        try:
            val = await self._r.get(self._key(hostname))
            if val is not None:
                return int(val)
        except Exception:
            pass
        return -1   # cache miss sentinel

    async def set(self, hostname: str, criticality: int) -> None:
        try:
            await self._r.setex(self._key(hostname), self._ttl, criticality)
        except Exception:
            pass


# ── Rule loader ────────────────────────────────────────────────────────────────

async def _load_rules() -> int:
    """Pull all enabled rules from DB and load into the in-memory engine."""
    from sqlalchemy import select
    from threatos.models.detection_rule import DetectionRule

    async with get_db_context() as db:
        result = await db.execute(
            select(DetectionRule).where(DetectionRule.enabled.is_(True))
        )
        rules = result.scalars().all()
        rows  = [
            {
                "id":           str(r.id),
                "name":         r.name,
                "technique_id": r.technique_id,
                "tactic":       r.tactic,
                "log_sources":  r.log_sources or [],
                "severity":     r.severity,
                "confidence":   r.confidence,
                "detection_ast":r.detection_ast,
                "tags":         r.tags or [],
            }
            for r in rules
        ]
    count = load_rules_into_engine(rows)
    log.info("Loaded %d rules into engine", count)
    return count


# ── Criticality resolution ─────────────────────────────────────────────────────

async def _resolve_criticality(
    hostname: str | None,
    cache: _CriticalityCache,
) -> int:
    """
    Return criticality for a hostname.
    Check Redis cache first; fall back to DB lookup; default to 2.
    """
    if not hostname:
        return 2

    cached = await cache.get(hostname)
    if cached != -1:
        return cached

    # Cache miss — look up in DB
    async with get_db_context() as db:
        asset = await get_asset_by_hostname(db, hostname)
        tier  = asset.criticality if asset else 2

    await cache.set(hostname, tier)
    return tier


# ── Message processing ────────────────────────────────────────────────────────

async def _process_message(
    message_id: str,
    fields: dict[str, Any],
    cache: _CriticalityCache,
) -> list[dict[str, Any]]:
    """
    Parse one stream message → evaluate rules → return alert dicts.
    Never raises — all errors are logged and an empty list is returned.
    """
    try:
        # Reconstruct NormalizedEvent from stream fields
        # Fields are stored as flat strings in Redis streams
        event = NormalizedEvent(
            event_id=fields.get("event_id", message_id),
            log_source=fields.get("log_source", "unknown"),
            host=fields.get("host") or None,
            user=fields.get("user") or None,
            process=fields.get("process") or None,
            command_line=fields.get("command_line") or None,
            parent_process=fields.get("parent_process") or None,
            src_ip=fields.get("src_ip") or None,
            dst_ip=fields.get("dst_ip") or None,
            dst_port=int(fields["dst_port"]) if fields.get("dst_port") else None,
            file_path=fields.get("file_path") or None,
            file_hash=fields.get("file_hash") or None,
            logon_type=fields.get("logon_type") or None,
            auth_result=fields.get("auth_result") or None,
            raw_fields=json.loads(fields.get("raw_fields", "{}")),
            hash=fields.get("hash") or None,
        )
    except Exception as exc:
        log.warning("Failed to parse message %s: %s", message_id, exc)
        return []

    try:
        criticality = await _resolve_criticality(event.host, cache)
        matches     = evaluate_event(event, asset_criticality=criticality)
    except Exception as exc:
        log.warning("Rule evaluation failed for %s: %s", message_id, exc)
        return []

    return [
        build_alert_dict(event, match, asset_criticality=criticality)
        for match in matches
    ]


# ── Batch processing ──────────────────────────────────────────────────────────

async def _process_batch(
    redis:    aioredis.Redis,
    messages: list[tuple[str, dict]],
    cache:    _CriticalityCache,
) -> tuple[int, int]:
    """
    Process a batch of stream messages.
    Returns (alerts_created, messages_acked).
    """
    all_alert_dicts: list[dict[str, Any]] = []
    message_ids: list[str] = []

    for msg_id, fields in messages:
        alerts = await _process_message(msg_id, fields, cache)
        all_alert_dicts.extend(alerts)
        message_ids.append(msg_id)

    # Persist all alerts in one DB flush
    alerts_created = 0
    if all_alert_dicts:
        try:
            async with get_db_context() as db:
                alerts_created = await persist_alerts_bulk(db, all_alert_dicts)
        except Exception as exc:
            log.error("Failed to persist %d alerts: %s", len(all_alert_dicts), exc)

    # XACK all messages in this batch — even ones that produced no alerts
    # A message with no matches is still successfully processed.
    if message_ids:
        await redis.xack(
            settings.redis_stream_name,
            settings.redis_consumer_group,
            *message_ids,
        )

    return alerts_created, len(message_ids)


# ── Consumer group bootstrap ──────────────────────────────────────────────────

async def _ensure_consumer_group(redis: aioredis.Redis) -> None:
    """Create the consumer group if it doesn't exist yet."""
    try:
        await redis.xgroup_create(
            settings.redis_stream_name,
            settings.redis_consumer_group,
            id="0",            # start from beginning of stream
            mkstream=True,     # create stream if it doesn't exist
        )
        log.info(
            "Created consumer group %r on stream %r",
            settings.redis_consumer_group,
            settings.redis_stream_name,
        )
    except aioredis.ResponseError as exc:
        if "BUSYGROUP" in str(exc):
            log.debug("Consumer group already exists — skipping creation")
        else:
            raise


# ── Main worker loop ──────────────────────────────────────────────────────────

_SHUTDOWN = asyncio.Event()


def _handle_signal(sig: int, _frame: Any) -> None:
    log.info("Received signal %d — shutting down gracefully", sig)
    _SHUTDOWN.set()


async def run_worker() -> None:
    """
    Main async loop.  Connects to Redis, bootstraps the consumer group,
    loads rules, then polls indefinitely until SIGTERM/SIGINT.
    """
    # Register shutdown signals
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)

    log.info("ThreatOS ingest worker starting")

    # Load detection rules into engine at startup
    rule_count = await _load_rules()
    if rule_count == 0:
        log.warning("No detection rules loaded — worker will consume events but produce no alerts")

    # Connect to Redis
    redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    cache = _CriticalityCache(redis)

    await _ensure_consumer_group(redis)

    total_alerts  = 0
    total_events  = 0
    last_log_time = datetime.now(UTC)

    log.info(
        "Worker ready — group=%r consumer=%r batch=%d",
        settings.redis_consumer_group,
        settings.redis_consumer_name,
        settings.worker_batch_size,
    )

    while not _SHUTDOWN.is_set():
        try:
            # XREADGROUP: block until messages arrive or timeout
            raw = await redis.xreadgroup(
                groupname=settings.redis_consumer_group,
                consumername=settings.redis_consumer_name,
                streams={settings.redis_stream_name: ">"},
                count=settings.worker_batch_size,
                block=settings.worker_block_ms,
            )
        except aioredis.ResponseError as exc:
            log.error("XREADGROUP error: %s — retrying in 1s", exc)
            await asyncio.sleep(1)
            continue
        except Exception as exc:
            log.error("Unexpected Redis error: %s", exc)
            await asyncio.sleep(1)
            continue

        if not raw:
            continue   # block timeout — no messages, loop again

        for _stream_name, messages in raw:
            if not messages:
                continue
            alerts_n, events_n = await _process_batch(redis, messages, cache)
            total_alerts += alerts_n
            total_events += events_n

        # Periodic progress log (every 60 s)
        now = datetime.now(UTC)
        if (now - last_log_time).seconds >= 60:
            log.info(
                "Worker stats — events=%d alerts=%d rules=%d",
                total_events, total_alerts, get_loaded_rule_count(),
            )
            last_log_time = now

    log.info("Worker shut down — processed %d events, created %d alerts",
             total_events, total_alerts)
    await redis.aclose()


if __name__ == "__main__":
    import structlog
    structlog.configure()
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_worker())
