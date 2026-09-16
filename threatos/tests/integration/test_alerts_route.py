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
import pytest_asyncio
from httpx import AsyncClient

from threatos.services.alert_service import persist_alert, persist_alerts_bulk


# ── Auth: all /api/alerts routes require an authenticated user ──────────────
# (see threatos/api/routers/alerts_router.py — Depends(get_current_user)).
# Bypass real JWT/API-key auth by overriding the dependency with a real,
# session-persisted admin user for the duration of each test.

@pytest_asyncio.fixture(autouse=True)
async def _authed_user(db_session):
    from threatos.core.dependencies import get_current_user
    from threatos.main import app
    from threatos.models.user import User

    user = User(
        id=str(uuid.uuid4()), username=f"itest-{uuid.uuid4().hex[:8]}",
        email=f"itest-{uuid.uuid4().hex[:8]}@example.com",
        password_hash="not-a-real-hash", role="admin", is_active=True,
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    await db_session.flush()

    async def _override():
        return user

    app.dependency_overrides[get_current_user] = _override
    yield user
    app.dependency_overrides.pop(get_current_user, None)


# ── Shared fixture: one seeded alert ─────────────────────────────────────────

def _make(
    technique_id: str = "T1059.001",
    tactic: str = "execution",
    risk_score: float = 52.5,
    status: str = "open",
    entity_host: str = "WIN-VICTIM",
) -> dict:
    # NOTE: persist_alert() (threatos/services/alert_service.py) does
    # `data.get("created_at") or datetime.now(UTC)` — it passes whatever is
    # given straight through to the DateTime column without parsing, so this
    # must be a real datetime object (not an ISO string) for SQLite's strict
    # DateTime type; production callers (e.g. rule_engine.build_alert_dict)
    # always pass real datetime objects too.
    now = datetime.now(UTC)
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

    # NOTE: the list route's response shape (get_alerts in alerts_router.py)
    # only projects this subset of fields — confidence, asset_criticality
    # and updated_at are returned by the single-alert GET but not by the
    # list route.
    required_fields = {
        "id", "technique_id", "tactic", "severity",
        "risk_score", "status",
        "entity_host", "entity_user", "created_at",
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
async def test_list_alerts_filter_by_min_risk(
    test_client: AsyncClient, db_session
):
    # NOTE: the query param is `min_risk` (see AlertFilters/get_alerts in
    # alerts_router.py) — the historical `min_score` name no longer exists
    # and is silently ignored by FastAPI as an unrecognised query param.
    await persist_alerts_bulk(db_session, [
        _make(risk_score=30.0),
        _make(risk_score=80.0),
    ])
    await db_session.commit()

    resp = await test_client.get("/api/alerts?min_risk=60")
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
async def test_list_alerts_very_high_min_risk_returns_empty(
    test_client: AsyncClient, db_session
):
    # NOTE: current `min_risk` query param (float, Query(0.0)) has no upper
    # bound/range validation, so this no longer 422s like the historical
    # `min_score` param did — it's a legitimate filter value that simply
    # excludes every alert.
    await persist_alerts_bulk(db_session, [_make(risk_score=30.0), _make(risk_score=80.0)])
    await db_session.commit()

    resp = await test_client.get("/api/alerts?min_risk=999")
    assert resp.status_code == 200
    assert resp.json() == []


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
