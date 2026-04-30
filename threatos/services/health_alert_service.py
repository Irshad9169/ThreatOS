from __future__ import annotations
import logging
import os
from datetime import UTC, datetime, timedelta
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.attck_kb import get_cache_size
from threatos.core.redis_client import get_redis_client
from threatos.detection.rule_engine import get_loaded_rule_count
from threatos.models.alert import Alert
from threatos.models.detection_rule import DetectionRule
from threatos.models.raw_event import RawEvent

log = logging.getLogger(__name__)

# Alert thresholds
WORKER_LAG_THRESHOLD     = int(os.environ.get("ALERT_WORKER_LAG",        "1000"))
NO_EVENTS_HOURS          = int(os.environ.get("ALERT_NO_EVENTS_HOURS",   "2"))
MIN_RULES_THRESHOLD      = int(os.environ.get("ALERT_MIN_RULES",         "100"))
COVERAGE_DROP_THRESHOLD  = float(os.environ.get("ALERT_COVERAGE_DROP",   "10.0"))

_last_coverage_pct: float = 0.0

async def run_health_checks(db: AsyncSession) -> list[dict]:
    """
    Run all health checks. Returns list of active alerts.
    Each alert has: level (critical/warning/info), check, message.
    """
    alerts = []
    now    = datetime.now(UTC)

    # 1. Worker lag check
    try:
        redis  = get_redis_client()
        stream = os.environ.get("REDIS_STREAM_NAME", "threatos:events:normalized")
        group  = os.environ.get("REDIS_CONSUMER_GROUP", "detection-workers")
        info   = await redis.xpending(stream, group)
        lag    = int(info.get("pending", 0))
        if lag > WORKER_LAG_THRESHOLD:
            alerts.append({
                "level":   "critical",
                "check":   "worker_lag",
                "message": f"Worker lag is {lag} events (threshold: {WORKER_LAG_THRESHOLD}). "
                           f"Ingest worker may be down or overwhelmed.",
                "value":   lag,
            })
            log.warning("HEALTH ALERT: Worker lag %d events", lag)
    except Exception as exc:
        alerts.append({
            "level":   "warning",
            "check":   "redis_connection",
            "message": f"Cannot check worker lag — Redis error: {exc}",
        })

    # 2. No events ingested recently
    cutoff = now - timedelta(hours=NO_EVENTS_HOURS)
    result = await db.execute(
        select(func.count(RawEvent.id))
        .where(RawEvent.received_at >= cutoff)
    )
    recent_events = int(result.scalar() or 0)
    if recent_events == 0:
        alerts.append({
            "level":   "warning",
            "check":   "no_recent_events",
            "message": f"No events ingested in the last {NO_EVENTS_HOURS} hours. "
                       f"Log pipeline may be broken.",
            "value":   0,
        })
        log.warning("HEALTH ALERT: No events in last %d hours", NO_EVENTS_HOURS)

    # 3. Rule count dropped significantly
    result = await db.execute(
        select(func.count(DetectionRule.id))
        .where(DetectionRule.enabled.is_(True))
    )
    enabled_rules = int(result.scalar() or 0)
    if enabled_rules < MIN_RULES_THRESHOLD:
        alerts.append({
            "level":   "critical",
            "check":   "rule_count_low",
            "message": f"Only {enabled_rules} rules enabled (threshold: {MIN_RULES_THRESHOLD}). "
                       f"Detection capability severely degraded.",
            "value":   enabled_rules,
        })
        log.error("HEALTH ALERT: Only %d rules enabled", enabled_rules)

    # 4. Engine not loaded
    loaded = get_loaded_rule_count()
    if loaded == 0 and enabled_rules > 0:
        alerts.append({
            "level":   "critical",
            "check":   "engine_empty",
            "message": f"Rule engine has 0 rules loaded but {enabled_rules} are enabled in DB. "
                       f"Events are not being evaluated.",
            "value":   0,
        })
        log.error("HEALTH ALERT: Rule engine empty — no detection running")

    # 5. ATT&CK cache empty
    if get_cache_size() == 0:
        alerts.append({
            "level":   "warning",
            "check":   "attck_cache_empty",
            "message": "ATT&CK bundle not loaded. Coverage refresh will fail.",
        })

    # 6. Coverage drop detection
    global _last_coverage_pct
    from threatos.models.coverage_matrix import CoverageMatrix
    cov_total = await db.execute(select(func.count(CoverageMatrix.technique_id)))
    cov_covered = await db.execute(
        select(func.count(CoverageMatrix.technique_id))
        .where(CoverageMatrix.covered.is_(True))
    )
    total   = int(cov_total.scalar() or 0)
    covered = int(cov_covered.scalar() or 0)
    if total > 0:
        current_pct = round(covered / total * 100, 1)
        if _last_coverage_pct > 0:
            drop = _last_coverage_pct - current_pct
            if drop >= COVERAGE_DROP_THRESHOLD:
                alerts.append({
                    "level":   "warning",
                    "check":   "coverage_drop",
                    "message": f"ATT&CK coverage dropped {drop:.1f}% "
                               f"({_last_coverage_pct}% → {current_pct}%). "
                               f"Rules may have been bulk-disabled.",
                    "value":   drop,
                })
                log.warning("HEALTH ALERT: Coverage dropped %.1f%%", drop)
        _last_coverage_pct = current_pct

    return alerts

async def get_platform_status(db: AsyncSession) -> dict:
    """
    Comprehensive platform status for the health dashboard.
    """
    now    = datetime.now(UTC)
    checks = await run_health_checks(db)

    # DB check
    try:
        from sqlalchemy import text
        await db.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception as exc:
        db_status = f"error: {exc}"

    # Redis check
    try:
        await get_redis_client().ping()
        redis_status = "ok"
    except Exception as exc:
        redis_status = f"error: {exc}"

    # Recent metrics
    cutoff_1h = now - timedelta(hours=1)
    cutoff_24h = now - timedelta(hours=24)

    events_1h = await db.execute(
        select(func.count(RawEvent.id)).where(RawEvent.received_at >= cutoff_1h))
    events_24h = await db.execute(
        select(func.count(RawEvent.id)).where(RawEvent.received_at >= cutoff_24h))
    alerts_1h = await db.execute(
        select(func.count(Alert.id)).where(Alert.created_at >= cutoff_1h))
    alerts_24h = await db.execute(
        select(func.count(Alert.id)).where(Alert.created_at >= cutoff_24h))
    open_alerts = await db.execute(
        select(func.count(Alert.id)).where(Alert.status == "open"))

    return {
        "timestamp":      now.isoformat(),
        "overall_status": "critical" if any(a["level"]=="critical" for a in checks)
                          else "warning" if checks else "ok",
        "active_alerts":  checks,
        "components": {
            "database":     db_status,
            "redis":        redis_status,
            "rule_engine":  f"ok ({get_loaded_rule_count()} rules)",
            "attck_cache":  f"ok ({get_cache_size()} techniques)"
                            if get_cache_size() > 0 else "empty",
        },
        "metrics": {
            "events_last_1h":  int(events_1h.scalar() or 0),
            "events_last_24h": int(events_24h.scalar() or 0),
            "alerts_last_1h":  int(alerts_1h.scalar() or 0),
            "alerts_last_24h": int(alerts_24h.scalar() or 0),
            "open_alerts":     int(open_alerts.scalar() or 0),
            "rules_loaded":    get_loaded_rule_count(),
        },
    }
