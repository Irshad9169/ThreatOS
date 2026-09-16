"""
tests/unit/test_alert_service.py
──────────────────────────────────
Unit tests for alert_service.py.
All DB operations run against SQLite in-memory via the db_session fixture.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text

from threatos.models.alert import Alert, VALID_STATUSES
from threatos.services.alert_service import (
    AlertFilters,
    get_alert_by_id,
    list_alerts,
    persist_alert,
    persist_alerts_bulk,
    update_alert_status,
)


# ── Test data factories ────────────────────────────────────────────────────────

def _alert_dict(
    technique_id: str = "T1059.001",
    tactic: str = "execution",
    severity: int = 7,
    confidence: float = 0.85,
    risk_score: float = 29.75,
    status: str = "open",
    entity_host: str | None = "WIN-VICTIM",
    entity_user: str | None = "alice",
) -> dict:
    """Build a minimal alert dict matching build_alert_dict() output."""
    now = datetime.now(UTC).isoformat()
    return {
        "id":               str(uuid.uuid4()),
        "rule_id":          str(uuid.uuid4()),
        "event_id":         str(uuid.uuid4()),
        "technique_id":     technique_id,
        "tactic":           tactic,
        "severity":         severity,
        "confidence":       confidence,
        "asset_criticality":2,
        "risk_score":       risk_score,
        "entity_host":      entity_host,
        "entity_user":      entity_user,
        "entity_process":   "powershell.exe",
        "entity_ip":        None,
        "status":           status,
        "description":      f"Test alert for {technique_id}",
        "raw_match":        {"rule_name": "Test rule", "tags": [], "matched_fields": {}},
        "created_at":       now,
        "updated_at":       now,
    }


# ── persist_alert ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_persist_alert_inserts_row(db_session):
    d = _alert_dict()
    alert = await persist_alert(db_session, d)
    result = await db_session.execute(text("SELECT COUNT(*) FROM alerts"))
    assert result.scalar() == 1
    assert alert.technique_id == "T1059.001"

@pytest.mark.asyncio
async def test_persist_alert_returns_correct_fields(db_session):
    d = _alert_dict(technique_id="T1003.001", tactic="credential-access",
                    severity=9, risk_score=81.0)
    alert = await persist_alert(db_session, d)
    assert alert.technique_id    == "T1003.001"
    assert alert.tactic          == "credential-access"
    assert alert.severity        == 9
    assert alert.risk_score      == 81.0
    assert alert.status          == "open"

@pytest.mark.asyncio
async def test_persist_alert_entity_fields(db_session):
    d = _alert_dict(entity_host="DC-01", entity_user="bob")
    alert = await persist_alert(db_session, d)
    assert alert.entity_host == "DC-01"
    assert alert.entity_user == "bob"

@pytest.mark.asyncio
async def test_persist_alert_none_entity_fields_allowed(db_session):
    d = _alert_dict(entity_host=None, entity_user=None)
    alert = await persist_alert(db_session, d)
    assert alert.entity_host is None
    assert alert.entity_user is None

@pytest.mark.asyncio
async def test_persist_alert_stores_raw_match(db_session):
    d = _alert_dict()
    d["raw_match"] = {"rule_name": "PowerShell enc", "tags": ["attack.t1059.001"]}
    alert = await persist_alert(db_session, d)
    assert alert.raw_match["rule_name"] == "PowerShell enc"


# ── persist_alerts_bulk ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_persist_bulk_inserts_all(db_session):
    dicts = [_alert_dict(technique_id="T1059.001"),
             _alert_dict(technique_id="T1003.001"),
             _alert_dict(technique_id="T1110")]
    count = await persist_alerts_bulk(db_session, dicts)
    assert count == 3
    result = await db_session.execute(text("SELECT COUNT(*) FROM alerts"))
    assert result.scalar() == 3

@pytest.mark.asyncio
async def test_persist_bulk_empty_list_returns_zero(db_session):
    count = await persist_alerts_bulk(db_session, [])
    assert count == 0
    result = await db_session.execute(text("SELECT COUNT(*) FROM alerts"))
    assert result.scalar() == 0


# ── get_alert_by_id ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_alert_by_id_returns_alert(db_session):
    d = _alert_dict()
    alert = await persist_alert(db_session, d)
    fetched = await get_alert_by_id(db_session, alert.id)
    assert fetched is not None
    assert fetched.id == alert.id

@pytest.mark.asyncio
async def test_get_alert_by_id_returns_none_when_missing(db_session):
    result = await get_alert_by_id(db_session, uuid.uuid4())
    assert result is None


# ── list_alerts ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_alerts_returns_all_unfiltered(db_session):
    await persist_alerts_bulk(db_session, [
        _alert_dict(technique_id="T1059.001"),
        _alert_dict(technique_id="T1003.001"),
        _alert_dict(technique_id="T1110"),
    ])
    alerts = await list_alerts(db_session)
    assert len(alerts) == 3

@pytest.mark.asyncio
async def test_list_alerts_ordered_by_risk_score_desc(db_session):
    await persist_alerts_bulk(db_session, [
        _alert_dict(risk_score=20.0),
        _alert_dict(risk_score=80.0),
        _alert_dict(risk_score=50.0),
    ])
    alerts = await list_alerts(db_session)
    scores = [a.risk_score for a in alerts]
    assert scores == sorted(scores, reverse=True)

@pytest.mark.asyncio
async def test_list_alerts_filter_by_status(db_session):
    await persist_alerts_bulk(db_session, [
        _alert_dict(status="open"),
        _alert_dict(status="open"),
        _alert_dict(status="closed"),
    ])
    alerts = await list_alerts(db_session, AlertFilters(status="open"))
    assert len(alerts) == 2
    assert all(a.status == "open" for a in alerts)

@pytest.mark.asyncio
async def test_list_alerts_filter_by_technique_id(db_session):
    await persist_alerts_bulk(db_session, [
        _alert_dict(technique_id="T1059.001"),
        _alert_dict(technique_id="T1059.001"),
        _alert_dict(technique_id="T1003.001"),
    ])
    alerts = await list_alerts(db_session, AlertFilters(technique_id="T1059.001"))
    assert len(alerts) == 2

@pytest.mark.asyncio
async def test_list_alerts_filter_by_min_score(db_session):
    await persist_alerts_bulk(db_session, [
        _alert_dict(risk_score=30.0),
        _alert_dict(risk_score=60.0),
        _alert_dict(risk_score=90.0),
    ])
    alerts = await list_alerts(db_session, AlertFilters(min_score=55.0))
    assert len(alerts) == 2
    assert all(a.risk_score >= 55.0 for a in alerts)

@pytest.mark.asyncio
async def test_list_alerts_filter_by_entity_host(db_session):
    await persist_alerts_bulk(db_session, [
        _alert_dict(entity_host="WIN-VICTIM"),
        _alert_dict(entity_host="WIN-VICTIM"),
        _alert_dict(entity_host="LINUX-01"),
    ])
    alerts = await list_alerts(db_session, AlertFilters(entity_host="WIN-VICTIM"))
    assert len(alerts) == 2

@pytest.mark.asyncio
async def test_list_alerts_pagination_limit(db_session):
    await persist_alerts_bulk(db_session, [_alert_dict() for _ in range(5)])
    alerts = await list_alerts(db_session, AlertFilters(limit=2))
    assert len(alerts) == 2

@pytest.mark.asyncio
async def test_list_alerts_pagination_offset(db_session):
    await persist_alerts_bulk(db_session, [_alert_dict() for _ in range(5)])
    page1 = await list_alerts(db_session, AlertFilters(limit=2, offset=0))
    page2 = await list_alerts(db_session, AlertFilters(limit=2, offset=2))
    ids1 = {a.id for a in page1}
    ids2 = {a.id for a in page2}
    assert ids1.isdisjoint(ids2)   # no overlap between pages

@pytest.mark.asyncio
async def test_list_alerts_empty_db_returns_empty_list(db_session):
    alerts = await list_alerts(db_session)
    assert alerts == []


# ── update_alert_status ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_status_changes_to_investigating(db_session):
    alert = await persist_alert(db_session, _alert_dict(status="open"))
    await db_session.commit()
    updated = await update_alert_status(db_session, alert.id, "investigating")
    assert updated is not None
    assert updated.status == "investigating"

@pytest.mark.asyncio
async def test_update_status_sets_closed_at_when_closed(db_session):
    alert = await persist_alert(db_session, _alert_dict())
    await db_session.commit()
    updated = await update_alert_status(db_session, alert.id, "closed")
    assert updated.closed_at is not None

@pytest.mark.asyncio
async def test_update_status_sets_closed_at_for_false_positive(db_session):
    alert = await persist_alert(db_session, _alert_dict())
    await db_session.commit()
    updated = await update_alert_status(db_session, alert.id, "false_positive")
    assert updated.closed_at is not None

@pytest.mark.asyncio
async def test_update_status_does_not_set_closed_at_for_escalated(db_session):
    alert = await persist_alert(db_session, _alert_dict())
    await db_session.commit()
    updated = await update_alert_status(db_session, alert.id, "escalated")
    assert updated.closed_at is None

@pytest.mark.asyncio
async def test_update_status_returns_none_for_missing_alert(db_session):
    result = await update_alert_status(db_session, uuid.uuid4(), "closed")
    assert result is None

@pytest.mark.asyncio
async def test_update_status_raises_for_invalid_status(db_session):
    alert = await persist_alert(db_session, _alert_dict())
    with pytest.raises(ValueError, match="Invalid status"):
        await update_alert_status(db_session, alert.id, "INVALID")

@pytest.mark.asyncio
async def test_all_valid_statuses_are_accepted(db_session):
    """Every status in VALID_STATUSES should work without error."""
    for status in VALID_STATUSES:
        alert = await persist_alert(db_session, _alert_dict())
        await db_session.commit()
        result = await update_alert_status(db_session, alert.id, status)
        assert result is not None
        assert result.status == status
