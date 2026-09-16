"""
services/alert_service.py
──────────────────────────
All business logic for alerts lives here.
Routes call these functions — routes themselves contain zero logic.

Functions:
  persist_alert(db, alert_dict)         insert one alert row
  persist_alerts_bulk(db, alert_dicts)  insert many alerts efficiently
  get_alert_by_id(db, alert_id)         fetch one alert or None
  list_alerts(db, filters)              filtered, paginated list
  update_alert_status(db, id, status)   update status + closed_at
  AlertFilters                          typed filter object
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from threatos.models.alert import VALID_STATUSES, Alert


# ── Filter object ─────────────────────────────────────────────────────────────

@dataclass
class AlertFilters:
    """
    Typed container for alert list query parameters.
    All fields are optional — omit to skip that filter.
    """
    status:        str | None  = None
    technique_id:  str | None  = None
    tactic:        str | None  = None
    entity_host:   str | None  = None
    min_score:     float       = 0.0
    limit:         int         = 50
    offset:        int         = 0


# ── Persistence ───────────────────────────────────────────────────────────────

async def persist_alert(db: AsyncSession, alert_dict: dict[str, Any]) -> Alert:
    """
    Insert one alert from a dict produced by rule_engine.build_alert_dict().
    Returns the persisted Alert ORM object.

    Handles the datetime conversion: alert_dict stores ISO strings,
    the ORM model needs datetime objects.
    """
    alert = Alert(
        id=uuid.UUID(alert_dict["id"])
            if isinstance(alert_dict["id"], str) else alert_dict["id"],
        rule_id=alert_dict.get("rule_id"),
        rule_name=alert_dict.get("raw_match", {}).get("rule_name"),
        event_id=alert_dict.get("event_id"),
        technique_id=alert_dict["technique_id"],
        tactic=alert_dict["tactic"],
        severity=int(alert_dict["severity"]),
        confidence=float(alert_dict["confidence"]),
        asset_criticality=int(alert_dict.get("asset_criticality", 2)),
        risk_score=float(alert_dict["risk_score"]),
        entity_host=alert_dict.get("entity_host"),
        entity_user=alert_dict.get("entity_user"),
        entity_process=alert_dict.get("entity_process"),
        entity_ip=alert_dict.get("entity_ip"),
        status=alert_dict.get("status", "open"),
        description=alert_dict.get("description"),
        raw_match=alert_dict.get("raw_match"),
        created_at=_parse_dt(alert_dict.get("created_at")),
        updated_at=_parse_dt(alert_dict.get("updated_at")),
    )
    db.add(alert)
    await db.flush()   # get the id without committing — caller controls commit
    return alert


async def persist_alerts_bulk(
    db: AsyncSession,
    alert_dicts: list[dict[str, Any]],
) -> int:
    """
    Insert multiple alerts in a single flush.
    Returns count of alerts persisted.
    Skips empty lists without hitting the DB.
    """
    if not alert_dicts:
        return 0

    alerts = []
    for d in alert_dicts:
        alert = Alert(
            id=uuid.UUID(d["id"]) if isinstance(d["id"], str) else d["id"],
            rule_id=d.get("rule_id"),
            rule_name=d.get("raw_match", {}).get("rule_name"),
            event_id=d.get("event_id"),
            technique_id=d["technique_id"],
            tactic=d["tactic"],
            severity=int(d["severity"]),
            confidence=float(d["confidence"]),
            asset_criticality=int(d.get("asset_criticality", 2)),
            risk_score=float(d["risk_score"]),
            entity_host=d.get("entity_host"),
            entity_user=d.get("entity_user"),
            entity_process=d.get("entity_process"),
            entity_ip=d.get("entity_ip"),
            status=d.get("status", "open"),
            description=d.get("description"),
            raw_match=d.get("raw_match"),
            created_at=_parse_dt(d.get("created_at")),
            updated_at=_parse_dt(d.get("updated_at")),
        )
        alerts.append(alert)

    db.add_all(alerts)
    await db.flush()
    return len(alerts)


# ── Queries ───────────────────────────────────────────────────────────────────

async def get_alert_by_id(
    db: AsyncSession,
    alert_id: uuid.UUID,
) -> Alert | None:
    """Fetch one alert by primary key. Returns None if not found."""
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id)
    )
    return result.scalar_one_or_none()


async def list_alerts(
    db: AsyncSession,
    filters: AlertFilters | None = None,
) -> list[Alert]:
    """
    Return a filtered, paginated list of alerts ordered by risk_score DESC.
    All filter fields are optional — pass AlertFilters() for unfiltered list.
    """
    f = filters or AlertFilters()

    q = select(Alert).order_by(Alert.risk_score.desc())

    if f.status:
        q = q.where(Alert.status == f.status)
    if f.technique_id:
        q = q.where(Alert.technique_id == f.technique_id)
    if f.tactic:
        q = q.where(Alert.tactic == f.tactic)
    if f.entity_host:
        q = q.where(Alert.entity_host == f.entity_host)
    if f.min_score > 0:
        q = q.where(Alert.risk_score >= f.min_score)

    q = q.limit(f.limit).offset(f.offset)
    result = await db.execute(q)
    return list(result.scalars().all())


# ── Mutations ─────────────────────────────────────────────────────────────────

async def update_alert_status(
    db: AsyncSession,
    alert_id: uuid.UUID,
    new_status: str,
) -> Alert | None:
    """
    Update an alert's status.
    Automatically sets closed_at when status becomes 'closed' or 'false_positive'.
    Returns the updated Alert, or None if not found.
    Raises ValueError for invalid status values.
    """
    if new_status not in VALID_STATUSES:
        raise ValueError(
            f"Invalid status {new_status!r}. "
            f"Must be one of: {VALID_STATUSES}"
        )

    now = datetime.now(UTC)
    values: dict[str, Any] = {
        "status":     new_status,
        "updated_at": now,
    }
    if new_status in ("closed", "false_positive"):
        values["closed_at"] = now

    result = await db.execute(
        update(Alert)
        .where(Alert.id == alert_id)
        .values(**values)
        .returning(Alert)
    )
    return result.scalar_one_or_none()


# ── Internal helpers ──────────────────────────────────────────────────────────

def _parse_dt(value: Any) -> datetime:
    """
    Parse an ISO 8601 string or return a datetime.
    Falls back to UTC now if the value is None or unparseable.
    """
    if value is None:
        return datetime.now(UTC)
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return datetime.now(UTC)
