"""
tests/integration/test_scans_route.py
───────────────────────────────────────
Integration tests for /api/scans routes.
_run_nmap is mocked — no real Nmap required.
Same command on Oracle Linux 8: python3.11 -m pytest threatos/tests/ -v
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import text

from threatos.services.nmap_service import create_scan


# ── Auth: /api/scans routes require an authenticated user; the mutating
# routes (POST create/run) further require the "engineer" or "admin" role
# (see threatos/api/routers/scans_router.py — Depends(get_current_user) /
# Depends(require_engineer)). Bypass real JWT/API-key auth by overriding the
# dependency with a real, session-persisted admin user (satisfies both).

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

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
    </ports>
    <os><osmatch name="Linux 5.x" accuracy="95"/></os>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports/>
  </host>
</nmaprun>"""

NMAP_OK    = (SAMPLE_XML, None)
NMAP_ERROR = ("", "Nmap binary not found at /usr/bin/nmap")


# ── POST /api/scans ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_and_run_returns_201(test_client: AsyncClient):
    with patch("threatos.services.nmap_service._run_nmap",
               new_callable=AsyncMock, return_value=NMAP_OK):
        resp = await test_client.post("/api/scans", json={
            "target": "10.0.0.0/24", "scan_type": "quick"
        })
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_create_and_run_completed_status(test_client: AsyncClient):
    with patch("threatos.services.nmap_service._run_nmap",
               new_callable=AsyncMock, return_value=NMAP_OK):
        resp = await test_client.post("/api/scans", json={
            "target": "10.0.0.1", "scan_type": "quick"
        })
    assert resp.json()["status"] == "completed"


@pytest.mark.asyncio
async def test_create_and_run_open_ports_populated(test_client: AsyncClient):
    with patch("threatos.services.nmap_service._run_nmap",
               new_callable=AsyncMock, return_value=NMAP_OK):
        resp = await test_client.post("/api/scans",
                                       json={"target": "10.0.0.1"})
    data = resp.json()
    assert data["hosts_up"]    == 1
    assert data["hosts_down"]  == 1
    assert len(data["open_ports"]) == 2


@pytest.mark.asyncio
async def test_create_and_run_response_schema(test_client: AsyncClient):
    with patch("threatos.services.nmap_service._run_nmap",
               new_callable=AsyncMock, return_value=NMAP_OK):
        resp = await test_client.post("/api/scans",
                                       json={"target": "10.0.0.1"})
    data = resp.json()
    required = {
        "id", "target", "scan_type", "status",
        "hosts_up", "hosts_down", "open_ports",
        "os_guesses", "duration_s",
    }
    assert required.issubset(set(data.keys()))


@pytest.mark.asyncio
async def test_create_and_run_nmap_failure_returns_failed(test_client: AsyncClient):
    with patch("threatos.services.nmap_service._run_nmap",
               new_callable=AsyncMock, return_value=NMAP_ERROR):
        resp = await test_client.post("/api/scans",
                                       json={"target": "10.0.0.1"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"]       == "failed"
    assert data["error_detail"] is not None


@pytest.mark.asyncio
async def test_create_and_run_invalid_scan_type_returns_422(test_client: AsyncClient):
    resp = await test_client.post("/api/scans",
                                   json={"target": "10.0.0.1", "scan_type": "INVALID"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_and_run_persists_to_db(
    test_client: AsyncClient, db_session
):
    with patch("threatos.services.nmap_service._run_nmap",
               new_callable=AsyncMock, return_value=NMAP_OK):
        await test_client.post("/api/scans", json={"target": "10.0.0.1"})

    count = (await db_session.execute(
        text("SELECT COUNT(*) FROM scan_results")
    )).scalar()
    assert count == 1


# ── POST /api/scans/create ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_pending_returns_201(test_client: AsyncClient):
    resp = await test_client.post("/api/scans/create",
                                   json={"target": "10.0.0.1"})
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_create_pending_status_is_pending(test_client: AsyncClient):
    resp = await test_client.post("/api/scans/create",
                                   json={"target": "10.0.0.1"})
    assert resp.json()["status"] == "pending"


@pytest.mark.asyncio
async def test_create_pending_invalid_type_returns_422(test_client: AsyncClient):
    resp = await test_client.post("/api/scans/create",
                                   json={"target": "10.0.0.1", "scan_type": "BAD"})
    assert resp.status_code == 422


# ── POST /api/scans/{id}/run ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_existing_scan_completes(
    test_client: AsyncClient, db_session
):
    scan = await create_scan(db_session, "10.0.0.1", scan_type="quick")
    await db_session.commit()

    with patch("threatos.services.nmap_service._run_nmap",
               new_callable=AsyncMock, return_value=NMAP_OK):
        resp = await test_client.post(f"/api/scans/{scan.id}/run")

    assert resp.status_code == 200
    assert resp.json()["status"] == "completed"


@pytest.mark.asyncio
async def test_run_nonexistent_scan_returns_404(test_client: AsyncClient):
    resp = await test_client.post(f"/api/scans/{uuid.uuid4()}/run")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_run_non_pending_scan_returns_422(
    test_client: AsyncClient, db_session
):
    scan = await create_scan(db_session, "10.0.0.1")
    scan.status = "completed"
    await db_session.commit()

    resp = await test_client.post(f"/api/scans/{scan.id}/run")
    assert resp.status_code == 422


# ── GET /api/scans ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_scans_empty_returns_200(test_client: AsyncClient):
    resp = await test_client.get("/api/scans")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_scans_returns_created_scans(
    test_client: AsyncClient, db_session
):
    for target in ("10.0.0.1", "10.0.0.2"):
        await create_scan(db_session, target)
    await db_session.commit()

    resp = await test_client.get("/api/scans")
    assert len(resp.json()) == 2


@pytest.mark.asyncio
async def test_list_scans_filter_by_target(
    test_client: AsyncClient, db_session
):
    await create_scan(db_session, "10.0.0.1")
    await create_scan(db_session, "10.0.0.2")
    await db_session.commit()

    resp = await test_client.get("/api/scans?target=10.0.0.1")
    assert len(resp.json()) == 1
    assert resp.json()[0]["target"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_list_scans_filter_by_status(
    test_client: AsyncClient, db_session
):
    with patch("threatos.services.nmap_service._run_nmap",
               new_callable=AsyncMock, return_value=NMAP_OK):
        await test_client.post("/api/scans", json={"target": "10.0.0.1"})
    await create_scan(db_session, "10.0.0.2")
    await db_session.commit()

    resp = await test_client.get("/api/scans?status=completed")
    assert len(resp.json()) == 1
    assert resp.json()[0]["status"] == "completed"


# ── GET /api/scans/{id} ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_scan_by_id(test_client: AsyncClient, db_session):
    scan = await create_scan(db_session, "10.0.0.1")
    await db_session.commit()

    resp = await test_client.get(f"/api/scans/{scan.id}")
    assert resp.status_code == 200
    assert resp.json()["target"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_get_scan_404_on_missing(test_client: AsyncClient):
    resp = await test_client.get("/api/scans/nonexistent")
    assert resp.status_code == 404
