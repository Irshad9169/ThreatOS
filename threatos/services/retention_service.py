from __future__ import annotations
import logging
import os
from datetime import UTC, datetime, timedelta
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.database import get_db_context
from threatos.models.audit_log import AuditLog
from threatos.models.raw_event import RawEvent
from threatos.models.token_blacklist import TokenBlacklist
from threatos.models.login_attempt import LoginAttempt
from threatos.models.alert import Alert
from threatos.models.scan_result import ScanResult

log = logging.getLogger(__name__)

# Retention periods from environment
RAW_EVENTS_DAYS      = int(os.environ.get("RAW_EVENTS_RETENTION_DAYS",      "90"))
AUDIT_LOGS_DAYS      = int(os.environ.get("AUDIT_LOG_RETENTION_DAYS",       "365"))
LOGIN_ATTEMPTS_HOURS = int(os.environ.get("LOGIN_ATTEMPTS_RETENTION_HOURS", "24"))
SCAN_RESULTS_DAYS    = int(os.environ.get("SCAN_RESULTS_RETENTION_DAYS",    "180"))
CLOSED_ALERTS_DAYS   = int(os.environ.get("CLOSED_ALERTS_RETENTION_DAYS",   "365"))

async def run_retention(db: AsyncSession) -> dict:
    """
    Delete expired data per retention policy.
    Returns counts of deleted rows per table.
    Never deletes open alerts, active tokens, or audit logs under retention period.
    """
    now     = datetime.now(UTC)
    deleted = {}

    # 1. Raw events — delete after RAW_EVENTS_DAYS
    cutoff = now - timedelta(days=RAW_EVENTS_DAYS)
    result = await db.execute(
        delete(RawEvent).where(RawEvent.received_at < cutoff)
        .returning(RawEvent.id)
    )
    deleted["raw_events"] = len(result.fetchall())
    log.info("Retention: deleted %d raw_events older than %d days",
             deleted["raw_events"], RAW_EVENTS_DAYS)

    # 2. Expired token blacklist entries
    result = await db.execute(
        delete(TokenBlacklist).where(TokenBlacklist.expires_at < now)
        .returning(TokenBlacklist.jti)
    )
    deleted["token_blacklist"] = len(result.fetchall())

    # 3. Old login attempts
    cutoff = now - timedelta(hours=LOGIN_ATTEMPTS_HOURS)
    result = await db.execute(
        delete(LoginAttempt).where(LoginAttempt.attempted_at < cutoff)
        .returning(LoginAttempt.id)
    )
    deleted["login_attempts"] = len(result.fetchall())

    # 4. Old closed/false_positive alerts
    cutoff = now - timedelta(days=CLOSED_ALERTS_DAYS)
    result = await db.execute(
        delete(Alert).where(
            Alert.status.in_(["closed","false_positive"]),
            Alert.updated_at < cutoff,
        ).returning(Alert.id)
    )
    deleted["alerts_closed"] = len(result.fetchall())
    log.info("Retention: deleted %d closed alerts older than %d days",
             deleted["alerts_closed"], CLOSED_ALERTS_DAYS)

    # 5. Old completed scan results
    cutoff = now - timedelta(days=SCAN_RESULTS_DAYS)
    result = await db.execute(
        delete(ScanResult).where(
            ScanResult.status.in_(["completed","failed","cancelled"]),
            ScanResult.started_at < cutoff,
        ).returning(ScanResult.id)
    )
    deleted["scan_results"] = len(result.fetchall())

    # 6. Audit logs — keep for AUDIT_LOGS_DAYS (compliance)
    # Only delete if over retention period
    cutoff = now - timedelta(days=AUDIT_LOGS_DAYS)
    result = await db.execute(
        delete(AuditLog).where(AuditLog.timestamp < cutoff)
        .returning(AuditLog.id)
    )
    deleted["audit_logs"] = len(result.fetchall())
    if deleted["audit_logs"] > 0:
        log.info("Retention: deleted %d audit_logs older than %d days",
                 deleted["audit_logs"], AUDIT_LOGS_DAYS)

    total = sum(deleted.values())
    log.info("Retention run complete — total deleted: %d rows", total)
    return deleted

async def get_table_sizes(db: AsyncSession) -> dict:
    """Return row counts and disk usage for all tables."""
    result = await db.execute(text("""
        SELECT
            relname AS table_name,
            n_live_tup AS row_count,
            pg_size_pretty(pg_total_relation_size(relid)) AS total_size,
            pg_total_relation_size(relid) AS size_bytes
        FROM pg_stat_user_tables
        WHERE schemaname = 'public'
        ORDER BY pg_total_relation_size(relid) DESC
    """))
    return {
        r.table_name: {
            "rows": r.row_count,
            "size": r.total_size,
            "bytes": r.size_bytes,
        }
        for r in result
    }

async def estimate_days_until_full(db: AsyncSession,
                                    threshold_gb: float = 20.0) -> dict:
    """
    Estimate how many days until disk fills up based on
    current raw_events growth rate.
    """
    # Events ingested in last 7 days
    cutoff = datetime.now(UTC) - timedelta(days=7)
    result = await db.execute(
        select(func.count(RawEvent.id)).where(RawEvent.received_at >= cutoff)
    )
    recent_count = int(result.scalar() or 0)

    # Total size
    sizes = await get_table_sizes(db)
    total_bytes = sum(v["bytes"] for v in sizes.values())
    threshold_bytes = threshold_gb * 1024**3

    if recent_count == 0:
        days_remaining = 9999
    else:
        # Estimate bytes per event
        raw_events_size = sizes.get("raw_events", {}).get("bytes", 0)
        total_raw = sizes.get("raw_events", {}).get("rows", 1) or 1
        bytes_per_event = raw_events_size / total_raw
        daily_rate = (recent_count / 7) * bytes_per_event
        remaining = threshold_bytes - total_bytes
        days_remaining = int(remaining / daily_rate) if daily_rate > 0 else 9999

    return {
        "total_db_size_mb":    round(total_bytes / 1024**2, 1),
        "threshold_gb":        threshold_gb,
        "events_last_7_days":  recent_count,
        "estimated_days_until_full": min(days_remaining, 9999),
        "tables": sizes,
    }
