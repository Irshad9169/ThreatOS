"""
tests/integration/test_chains_route.py
────────────────────────────────────────
Integration tests for POST/GET/PUT /api/chains routes.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import AsyncClient

from threatos.models.alert import Alert


# ── Auth: all /api/chains routes require an authenticated user (see
# threatos/api/routers/chains_router.py — Depends(get_current_user)).
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


def _alert(
    host:         str   = "WIN-VICTIM",
    technique_id: str   = "T1059.001",
    tactic:       str   = "execution",
    risk_score:   float = 52.5,
) -> Alert:
    # NOTE: Alert.id is a String(36) column (threatos/models/alert.py), not
    # a native UUID type — must pass a str, matching how persist_alert()
    # (alert_service.py) always does `str(data.get("id") or uuid.uuid4())`.
    now = datetime.now(UTC)
    return Alert(
        id=str(uuid.uuid4()),
        technique_id=technique_id,
        tactic=tactic,
        entity_host=host,
        severity=7, confidence=0.85,
        asset_criticality=2, risk_score=risk_score,
        status="open",
        created_at=now, updated_at=now,
    )


# ── POST /api/chains/correlate ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_correlate_no_alerts_returns_message(test_client: AsyncClient):
    resp = await test_client.post("/api/chains/correlate",
                                   json={"host": "unknown-host"})
    assert resp.status_code == 200
    assert "message" in resp.json()


@pytest.mark.asyncio
async def test_correlate_returns_chain_summary(
    test_client: AsyncClient, db_session
):
    db_session.add(_alert(host="WIN-TARGET"))
    await db_session.commit()

    resp = await test_client.post("/api/chains/correlate",
                                   json={"host": "WIN-TARGET"})
    assert resp.status_code == 200
    data = resp.json()
    assert "chain_id"     in data
    assert "host"         in data
    assert "alert_count"  in data
    assert data["alert_count"] == 1


@pytest.mark.asyncio
async def test_correlate_multi_stage_detected(
    test_client: AsyncClient, db_session
):
    for tactic, tid in [
        ("initial-access",       "T1566"),
        ("execution",            "T1059.001"),
        ("privilege-escalation", "T1548"),
    ]:
        db_session.add(_alert(host="MULTI-HOST", technique_id=tid, tactic=tactic))
    await db_session.commit()

    resp = await test_client.post("/api/chains/correlate",
                                   json={"host": "MULTI-HOST"})
    data = resp.json()
    assert data["is_multi_stage"] is True
    assert data["tactic_count"]   == 3


@pytest.mark.asyncio
async def test_correlate_is_idempotent(test_client: AsyncClient, db_session):
    db_session.add(_alert(host="IDEM-HOST"))
    await db_session.commit()

    r1 = (await test_client.post("/api/chains/correlate",
                                  json={"host": "IDEM-HOST"})).json()
    r2 = (await test_client.post("/api/chains/correlate",
                                  json={"host": "IDEM-HOST"})).json()
    assert r1["chain_id"] == r2["chain_id"]


# ── GET /api/chains ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_chains_empty_returns_200(test_client: AsyncClient):
    resp = await test_client.get("/api/chains")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_chains_returns_created_chains(
    test_client: AsyncClient, db_session
):
    for host in ("H1", "H2"):
        db_session.add(_alert(host=host))
    await db_session.commit()
    for host in ("H1", "H2"):
        await test_client.post("/api/chains/correlate", json={"host": host})

    resp = await test_client.get("/api/chains")
    assert len(resp.json()) == 2


@pytest.mark.asyncio
async def test_list_chains_response_schema(
    test_client: AsyncClient, db_session
):
    db_session.add(_alert(host="SCHEMA-HOST"))
    await db_session.commit()
    await test_client.post("/api/chains/correlate", json={"host": "SCHEMA-HOST"})

    chain = (await test_client.get("/api/chains")).json()[0]
    required = {
        "id", "host", "tactic_count", "technique_ids",
        "tactics_observed", "alert_ids", "risk_score",
        "is_multi_stage", "status", "first_seen",
    }
    assert required.issubset(set(chain.keys()))


@pytest.mark.asyncio
async def test_list_chains_filter_by_host(
    test_client: AsyncClient, db_session
):
    for host in ("WIN-A", "WIN-B"):
        db_session.add(_alert(host=host))
    await db_session.commit()
    for host in ("WIN-A", "WIN-B"):
        await test_client.post("/api/chains/correlate", json={"host": host})

    resp  = await test_client.get("/api/chains?host=WIN-A")
    chains = resp.json()
    assert len(chains) == 1
    assert chains[0]["host"] == "win-a"


@pytest.mark.asyncio
async def test_list_chains_filter_multi_stage(
    test_client: AsyncClient, db_session
):
    for tactic, tid in [
        ("initial-access","T1566"),("execution","T1059.001"),("persistence","T1547")
    ]:
        db_session.add(_alert(host="MULTI", technique_id=tid, tactic=tactic))
    db_session.add(_alert(host="SINGLE"))
    await db_session.commit()
    await test_client.post("/api/chains/correlate", json={"host": "MULTI"})
    await test_client.post("/api/chains/correlate", json={"host": "SINGLE"})

    resp = await test_client.get("/api/chains?is_multi_stage=true")
    assert len(resp.json()) == 1


# ── GET /api/chains/{id} ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_chain_by_id(test_client: AsyncClient, db_session):
    db_session.add(_alert(host="ID-HOST"))
    await db_session.commit()
    corr = (await test_client.post("/api/chains/correlate",
                                    json={"host": "ID-HOST"})).json()
    chain_id = corr["chain_id"]

    resp = await test_client.get(f"/api/chains/{chain_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == chain_id


@pytest.mark.asyncio
async def test_get_chain_404_on_missing(test_client: AsyncClient):
    resp = await test_client.get(f"/api/chains/{uuid.uuid4()}")
    assert resp.status_code == 404


# ── PUT /api/chains/{id}/status ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_chain_status(test_client: AsyncClient, db_session):
    db_session.add(_alert(host="STATUS-HOST"))
    await db_session.commit()
    corr     = (await test_client.post("/api/chains/correlate",
                                        json={"host": "STATUS-HOST"})).json()
    chain_id = corr["chain_id"]

    resp = await test_client.put(f"/api/chains/{chain_id}/status",
                                  json={"status": "investigating"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "investigating"


@pytest.mark.asyncio
async def test_update_chain_invalid_status_returns_400(
    test_client: AsyncClient, db_session
):
    db_session.add(_alert(host="BADSTATUS"))
    await db_session.commit()
    corr     = (await test_client.post("/api/chains/correlate",
                                        json={"host": "BADSTATUS"})).json()
    chain_id = corr["chain_id"]

    resp = await test_client.put(f"/api/chains/{chain_id}/status",
                                  json={"status": "INVALID"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_update_chain_404_on_missing(test_client: AsyncClient):
    resp = await test_client.put(f"/api/chains/{uuid.uuid4()}/status",
                                  json={"status": "closed"})
    assert resp.status_code == 404
