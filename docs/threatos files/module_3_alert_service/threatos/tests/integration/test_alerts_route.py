"""
tests/integration/test_alerts_route.py
──────────────────────────────────────
Integration tests for GET/PUT /api/alerts routes.
Seeds alert rows directly via the service layer,
then calls the HTTP routes to verify request → response.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient

from threatos.services.alert_service import persist_alert, persist_alerts_bulk


# ── Shared fixture: one seeded alert ─────────────────────────────────────────

def _make(
    technique_id: str = "T1059.001",
    tactic: str = "execution",
    risk_score: float = 52.5,
    status: str = "open",
    entity_host: str = "WIN-VICTIM",
) -> dict:
    now = datetime.now(UTC).isoformat()
    return {
        "id":               str(uuid.uuid4()),
        "rule_id":          "rule-123",
        "event_id":         "evt-456",
        "technique_id":     technique_id,
        "tactic":           tactic,
        "severity":         7,
        "confidence":       0.85,
        "asset_criticality":2,
        "risk_score":       risk_score,
        "entity_host":      entity_host,
        "entity_user":      "alice",
        "entity_process":   "powershell.exe",
        "entity_ip":        None,
        "status":           status,
        "description":      f"Test alert {technique_id}",
        "raw_match":        {"rule_name": "Test rule"},
        "created_at":       now,
        "updated_at":       now,
    }


# ── GET /api/alerts ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_alerts_empty_returns_200(test_client: AsyncClient):
    resp = await test_client.get("/api/alerts")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_alerts_returns_seeded_alerts(
    test_client: AsyncClient, db_session
):
    await persist_alerts_bulk(db_session, [_make(), _make()])
    await db_session.commit()

    resp = await test_client.get("/api/alerts")
    assert resp.status_code == 200
    assert len(resp.json()) == 2


@pytest.mark.asyncio
async def test_list_alerts_response_schema(
    test_client: AsyncClient, db_session
):
    await persist_alert(db_session, _make())
    await db_session.commit()

    resp = await test_client.get("/api/alerts")
    alert = resp.json()[0]

    required_fields = {
        "id", "technique_id", "tactic", "severity", "confidence",
        "risk_score", "asset_criticality", "status",
        "entity_host", "entity_user", "created_at", "updated_at",
    }
    assert required_fields.issubset(set(alert.keys()))


@pytest.mark.asyncio
async def test_list_alerts_ordered_by_risk_score_desc(
    test_client: AsyncClient, db_session
):
    await persist_alerts_bulk(db_session, [
        _make(risk_score=20.0),
        _make(risk_score=90.0),
        _make(risk_score=55.0),
    ])
    await db_session.commit()

    resp = await test_client.get("/api/alerts")
    scores = [a["risk_score"] for a in resp.json()]
    assert scores == sorted(scores, reverse=True)


@pytest.mark.asyncio
async def test_list_alerts_filter_by_status(
    test_client: AsyncClient, db_session
):
    await persist_alerts_bulk(db_session, [
        _make(status="open"),
        _make(status="open"),
        _make(status="closed"),
    ])
    await db_session.commit()

    resp = await test_client.get("/api/alerts?status=open")
    assert len(resp.json()) == 2
    assert all(a["status"] == "open" for a in resp.json())


@pytest.mark.asyncio
async def test_list_alerts_filter_by_technique(
    test_client: AsyncClient, db_session
):
    await persist_alerts_bulk(db_session, [
        _make(technique_id="T1059.001"),
        _make(technique_id="T1059.001"),
        _make(technique_id="T1003.001"),
    ])
    await db_session.commit()

    resp = await test_client.get("/api/alerts?technique_id=T1059.001")
    assert len(resp.json()) == 2


@pytest.mark.asyncio
async def test_list_alerts_filter_by_min_score(
    test_client: AsyncClient, db_session
):
    await persist_alerts_bulk(db_session, [
        _make(risk_score=30.0),
        _make(risk_score=80.0),
    ])
    await db_session.commit()

    resp = await test_client.get("/api/alerts?min_score=60")
    data = resp.json()
    assert len(data) == 1
    assert data[0]["risk_score"] == 80.0


@pytest.mark.asyncio
async def test_list_alerts_pagination(
    test_client: AsyncClient, db_session
):
    await persist_alerts_bulk(db_session, [_make() for _ in range(5)])
    await db_session.commit()

    resp = await test_client.get("/api/alerts?limit=2&offset=0")
    assert len(resp.json()) == 2


@pytest.mark.asyncio
async def test_list_alerts_invalid_min_score_returns_422(test_client: AsyncClient):
    resp = await test_client.get("/api/alerts?min_score=999")
    assert resp.status_code == 422


# ── GET /api/alerts/{id} ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_alert_by_id_returns_200(
    test_client: AsyncClient, db_session
):
    alert = await persist_alert(db_session, _make())
    await db_session.commit()

    resp = await test_client.get(f"/api/alerts/{alert.id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == str(alert.id)


@pytest.mark.asyncio
async def test_get_alert_by_id_returns_404_when_missing(test_client: AsyncClient):
    resp = await test_client.get(f"/api/alerts/{uuid.uuid4()}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_alert_by_id_technique_matches(
    test_client: AsyncClient, db_session
):
    alert = await persist_alert(db_session, _make(technique_id="T1110"))
    await db_session.commit()

    resp = await test_client.get(f"/api/alerts/{alert.id}")
    assert resp.json()["technique_id"] == "T1110"


# ── PUT /api/alerts/{id}/status ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_status_returns_200(
    test_client: AsyncClient, db_session
):
    alert = await persist_alert(db_session, _make(status="open"))
    await db_session.commit()

    resp = await test_client.put(
        f"/api/alerts/{alert.id}/status",
        json={"status": "investigating"},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_update_status_reflects_new_status(
    test_client: AsyncClient, db_session
):
    alert = await persist_alert(db_session, _make(status="open"))
    await db_session.commit()

    resp = await test_client.put(
        f"/api/alerts/{alert.id}/status",
        json={"status": "investigating"},
    )
    assert resp.json()["status"] == "investigating"


@pytest.mark.asyncio
async def test_update_status_closed_sets_closed_at(
    test_client: AsyncClient, db_session
):
    alert = await persist_alert(db_session, _make())
    await db_session.commit()

    resp = await test_client.put(
        f"/api/alerts/{alert.id}/status",
        json={"status": "closed"},
    )
    assert resp.json()["closed_at"] is not None


@pytest.mark.asyncio
async def test_update_status_invalid_returns_400(
    test_client: AsyncClient, db_session
):
    alert = await persist_alert(db_session, _make())
    await db_session.commit()

    resp = await test_client.put(
        f"/api/alerts/{alert.id}/status",
        json={"status": "NONSENSE"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_update_status_missing_alert_returns_404(test_client: AsyncClient):
    resp = await test_client.put(
        f"/api/alerts/{uuid.uuid4()}/status",
        json={"status": "closed"},
    )
    assert resp.status_code == 404
