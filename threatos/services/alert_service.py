from __future__ import annotations
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
import uuid
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.models.alert import Alert

VALID_STATUSES = ("open","investigating","escalated","closed","false_positive")

@dataclass
class AlertFilters:
    status:       str | None  = None
    technique_id: str | None  = None
    entity_host:  str | None  = None
    min_risk:     float       = 0.0
    limit:        int         = 100
    offset:       int         = 0

async def persist_alert(db: AsyncSession, data: dict) -> Alert:
    alert = Alert(
        id=str(data.get("id") or uuid.uuid4()),
        rule_id=data.get("rule_id"), rule_name=data.get("rule_name"),
        event_id=data.get("event_id"), technique_id=data["technique_id"],
        tactic=data["tactic"], severity=data["severity"],
        confidence=data["confidence"],
        asset_criticality=data.get("asset_criticality", 2),
        risk_score=data["risk_score"],
        entity_host=data.get("entity_host"), entity_user=data.get("entity_user"),
        entity_process=data.get("entity_process"), entity_ip=data.get("entity_ip"),
        status=data.get("status","open"),
        created_at=data.get("created_at") or datetime.now(UTC),
        updated_at=data.get("updated_at") or datetime.now(UTC),
        raw_match=data.get("raw_match"),
    )
    db.add(alert)
    await db.flush()
    return alert

async def persist_alerts_bulk(db: AsyncSession, alerts: list[dict]) -> int:
    count = 0
    for a in alerts:
        try:
            await persist_alert(db, a)
            count += 1
        except Exception:
            pass
    return count

async def list_alerts(db: AsyncSession, filters: AlertFilters | None = None) -> list[Alert]:
    f = filters or AlertFilters()
    q = select(Alert).order_by(Alert.risk_score.desc(), Alert.created_at.desc())
    if f.status:       q = q.where(Alert.status == f.status)
    if f.technique_id: q = q.where(Alert.technique_id == f.technique_id)
    if f.entity_host:  q = q.where(Alert.entity_host == f.entity_host)
    if f.min_risk > 0: q = q.where(Alert.risk_score >= f.min_risk)
    q = q.limit(f.limit).offset(f.offset)
    result = await db.execute(q)
    return list(result.scalars().all())

async def get_alert_by_id(db: AsyncSession, alert_id: str) -> Alert | None:
    result = await db.execute(select(Alert).where(Alert.id == str(alert_id)))
    return result.scalar_one_or_none()

async def update_alert_status(db: AsyncSession, alert_id: str, new_status: str) -> Alert | None:
    if new_status not in VALID_STATUSES:
        raise ValueError(f"Invalid status: {new_status!r}")
    values: dict[str, Any] = {"status": new_status, "updated_at": datetime.now(UTC)}
    if new_status in ("closed", "false_positive"):
        values["closed_at"] = datetime.now(UTC)
    result = await db.execute(
        update(Alert).where(Alert.id == str(alert_id))
        .values(**values)
        .returning(Alert)
    )
    return result.scalar_one_or_none()
