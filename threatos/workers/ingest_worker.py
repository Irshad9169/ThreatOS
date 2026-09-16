from __future__ import annotations
import asyncio, json, logging, signal, uuid
from datetime import UTC, datetime
from typing import Any
import redis.asyncio as aioredis
from threatos.core.database import get_db_context
from threatos.core.settings import settings
from threatos.detection.rule_engine import (
    build_alert_dict, evaluate_event, get_loaded_rule_count,
    load_rules_into_engine,
)
from threatos.ingestion.normalizer import NormalizedEvent
from threatos.services.alert_service import persist_alerts_bulk
from threatos.services.asset_service import get_asset_by_hostname
from threatos.services.suppression_service import is_suppressed

log = logging.getLogger(__name__)

# Pending message timeout — reclaim messages stuck for > 5 minutes
PENDING_TIMEOUT_MS = 5 * 60 * 1000

class _CriticalityCache:
    def __init__(self, redis: aioredis.Redis) -> None:
        self._r = redis
        self._ttl = settings.asset_criticality_ttl
    def _key(self, hostname: str) -> str:
        return f"threatos:asset:crit:{hostname.lower()}"
    async def get(self, hostname: str) -> int:
        try:
            val = await self._r.get(self._key(hostname))
            if val is not None: return int(val)
        except Exception: pass
        return -1
    async def set(self, hostname: str, criticality: int) -> None:
        try:
            await self._r.setex(self._key(hostname), self._ttl, criticality)
        except Exception: pass

async def _load_rules() -> int:
    from sqlalchemy import select
    from threatos.models.detection_rule import DetectionRule
    async with get_db_context() as db:
        result = await db.execute(
            select(DetectionRule).where(DetectionRule.enabled.is_(True)))
        rules = result.scalars().all()
        rows  = [{
            "id": str(r.id), "name": r.name,
            "technique_id": r.technique_id, "tactic": r.tactic,
            "log_sources": r.log_sources or [], "severity": r.severity,
            "confidence": r.confidence, "detection_ast": r.detection_ast,
            "tags": r.tags or [],
        } for r in rules]
    count = load_rules_into_engine(rows)
    log.info("Loaded %d rules into engine", count)
    return count

async def _resolve_criticality(hostname: str | None,
                                cache: _CriticalityCache) -> int:
    if not hostname: return 2
    cached = await cache.get(hostname)
    if cached != -1: return cached
    async with get_db_context() as db:
        asset = await get_asset_by_hostname(db, hostname)
        tier  = asset.criticality if asset else 2
    await cache.set(hostname, tier)
    return tier

async def _process_message(msg_id: str, fields: dict,
                            cache: _CriticalityCache) -> list[dict]:
    try:
        event = NormalizedEvent(
            event_id=fields.get("event_id", msg_id),
            log_source=fields.get("log_source", "unknown"),
            host=fields.get("host") or None,
            user=fields.get("user") or None,
            process=fields.get("process") or None,
            command_line=fields.get("command_line") or None,
            src_ip=fields.get("src_ip") or None,
            dst_ip=fields.get("dst_ip") or None,
            dst_port=int(fields["dst_port"]) if fields.get("dst_port","").isdigit() else None,
            raw_fields=json.loads(fields.get("raw_fields","{}")),
        )
    except Exception as exc:
        log.warning("Failed to parse message %s: %s", msg_id, exc)
        return []
    try:
        criticality = await _resolve_criticality(event.host, cache)
        matches     = evaluate_event(event, asset_criticality=criticality)
    except Exception as exc:
        log.warning("Rule eval failed for %s: %s", msg_id, exc)
        return []
    return matches

async def _check_suppression(alerts: list[dict]) -> list[dict]:
    """Filter out suppressed alerts (dedup within window)."""
    if not alerts:
        return []
    non_suppressed = []
    async with get_db_context() as db:
        for alert in alerts:
            rule_id = alert.get("rule_id","")
            host    = alert.get("entity_host")
            if await is_suppressed(db, rule_id, host):
                log.debug("Suppressed duplicate alert: rule=%s host=%s",
                          rule_id, host)
            else:
                non_suppressed.append(alert)
    return non_suppressed

async def _process_batch(redis: aioredis.Redis, messages: list,
                          cache: _CriticalityCache) -> tuple[int, int]:
    all_alerts: list[dict] = []
    msg_ids:    list[str]  = []
    for msg_id, fields in messages:
        alerts = await _process_message(msg_id, fields, cache)
        all_alerts.extend(alerts)
        msg_ids.append(msg_id)
    # Apply suppression
    all_alerts = await _check_suppression(all_alerts)
    alerts_created = 0
    if all_alerts:
        try:
            async with get_db_context() as db:
                alerts_created = await persist_alerts_bulk(db, all_alerts)
        except Exception as exc:
            log.error("Failed to persist %d alerts: %s", len(all_alerts), exc)
    # Acknowledge all messages (including ones that produced no alerts)
    if msg_ids:
        await redis.xack(settings.redis_stream_name,
                         settings.redis_consumer_group, *msg_ids)
    return alerts_created, len(msg_ids)

async def _reclaim_pending(redis: aioredis.Redis,
                            cache: _CriticalityCache) -> int:
    """
    XAUTOCLAIM — reclaim messages stuck in pending state for > PENDING_TIMEOUT_MS.
    This handles worker crash recovery: if this worker (or another) crashed
    mid-processing, those messages are re-claimed and re-processed.
    """
    try:
        result = await redis.xautoclaim(
            settings.redis_stream_name,
            settings.redis_consumer_group,
            settings.redis_consumer_name,
            min_idle_time=PENDING_TIMEOUT_MS,
            start_id="0-0",
            count=100,
        )
        # result format: [next_id, [[msg_id, fields], ...], [deleted_ids]]
        messages = result[1] if result and len(result) > 1 else []
        if messages:
            log.info("Reclaimed %d pending messages from crashed worker",
                     len(messages))
            alerts, events = await _process_batch(redis, messages, cache)
            return events
    except Exception as exc:
        log.warning("XAUTOCLAIM failed (Redis may not support it): %s", exc)
    return 0

_SHUTDOWN = asyncio.Event()

def _handle_signal(sig: int, _frame: Any) -> None:
    log.info("Signal %d received — shutting down", sig)
    _SHUTDOWN.set()

async def run_worker() -> None:
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)
    log.info("ThreatOS ingest worker starting")
    await _load_rules()
    redis = aioredis.from_url(settings.redis_url, decode_responses=True, protocol=2)
    cache = _CriticalityCache(redis)
    try:
        await redis.xgroup_create(
            settings.redis_stream_name,
            settings.redis_consumer_group,
            id="0", mkstream=True,
        )
    except aioredis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc): raise
    log.info("Worker ready — stream=%s group=%s suppression=enabled crash_recovery=enabled",
             settings.redis_stream_name, settings.redis_consumer_group)

    # Reclaim any pending messages from previous crashed workers
    await _reclaim_pending(redis, cache)

    total_alerts = 0; total_events = 0; idle_cycles = 0

    while not _SHUTDOWN.is_set():
        try:
            raw = await redis.xreadgroup(
                groupname=settings.redis_consumer_group,
                consumername=settings.redis_consumer_name,
                streams={settings.redis_stream_name: ">"},
                count=settings.worker_batch_size,
                block=settings.worker_block_ms,
            )
        except Exception as exc:
            log.error("XREADGROUP error: %s", exc)
            await asyncio.sleep(1)
            continue

        if not raw:
            idle_cycles += 1
            # Periodically check for pending messages (crash recovery)
            if idle_cycles % 100 == 0:
                await _reclaim_pending(redis, cache)
            continue

        idle_cycles = 0
        for _stream, messages in raw:
            if not messages: continue
            a, e = await _process_batch(redis, messages, cache)
            total_alerts += a
            total_events += e

    log.info("Worker shut down — events=%d alerts=%d",
             total_events, total_alerts)
    await redis.aclose()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s")
    asyncio.run(run_worker())
