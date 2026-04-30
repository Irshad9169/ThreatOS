from __future__ import annotations
import hashlib
from datetime import UTC, datetime, timedelta
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.models.alert import Alert

SUPPRESSION_WINDOW_MINUTES = 15  # default suppression window

def _suppression_key(rule_id: str, host: str | None) -> str:
    """Unique key for rule+host combination."""
    raw = f"{rule_id}|{host or 'unknown'}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

async def is_suppressed(db: AsyncSession, rule_id: str,
                         host: str | None,
                         window_minutes: int = SUPPRESSION_WINDOW_MINUTES) -> bool:
    """
    Check if an alert for this rule+host combination was already
    created within the suppression window.
    Returns True if suppressed (duplicate), False if should be created.
    """
    cutoff = datetime.now(UTC) - timedelta(minutes=window_minutes)
    result = await db.execute(
        select(func.count(Alert.id)).where(
            Alert.rule_id    == str(rule_id),
            Alert.entity_host == host,
            Alert.created_at  >= cutoff,
        )
    )
    count = result.scalar() or 0
    return count > 0

async def get_suppression_stats(db: AsyncSession,
                                 window_minutes: int = SUPPRESSION_WINDOW_MINUTES) -> dict:
    """How many alerts would have been suppressed in the last window."""
    cutoff = datetime.now(UTC) - timedelta(minutes=window_minutes)
    result = await db.execute(
        select(
            Alert.rule_id,
            Alert.entity_host,
            func.count(Alert.id).label("cnt")
        )
        .where(Alert.created_at >= cutoff)
        .group_by(Alert.rule_id, Alert.entity_host)
        .having(func.count(Alert.id) > 1)
        .order_by(func.count(Alert.id).desc())
    )
    rows = result.all()
    total_duplicates = sum(max(0, r.cnt - 1) for r in rows)
    return {
        "window_minutes":   window_minutes,
        "noisy_rule_hosts": len(rows),
        "duplicate_alerts": total_duplicates,
        "top_noisy": [
            {"rule_id": r.rule_id, "host": r.entity_host, "count": r.cnt}
            for r in rows[:10]
        ],
    }
