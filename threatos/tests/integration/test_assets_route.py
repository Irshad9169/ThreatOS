"""
tests/integration/test_assets_route.py
───────────────────────────────────────
Integration tests for /api/assets routes.
Seeds assets via the service, verifies HTTP responses.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import AsyncClient

from threatos.services.asset_service import AssetCreate, create_asset


# ── Auth: /api/assets routes require an authenticated user; the mutating
# routes (POST/PUT/DELETE) further require the "engineer" or "admin" role
# (see threatos/api/routers/assets_router.py — Depends(get_current_user) /
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


def _body(
    hostname:    str = "server01.corp",
    criticality: int = 2,
    environment: str = "production",
    owner_team:  str = "platform-eng",
) -> dict:
    return {
        "hostname":    hostname,
        "criticality": criticality,
        "environment": environment,
        "owner_team":  owner_team,
        "os_type":     "linux",
        "ip_addresses":["10.0.0.1"],
        "tags":        ["web"],
    }


# ── GET /api/assets ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_assets_empty_returns_200(test_client: AsyncClient):
    resp = await test_client.get("/api/assets")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_assets_returns_seeded_assets(
    test_client: AsyncClient, db_session
):
    await create_asset(db_session, AssetCreate(hostname="h1", environment="production"))
    await create_asset(db_session, AssetCreate(hostname="h2", environment="staging"))
    await db_session.commit()

    resp = await test_client.get("/api/assets")
    assert len(resp.json()) == 2


@pytest.mark.asyncio
async def test_list_assets_response_schema(
    test_client: AsyncClient, db_session
):
    await create_asset(db_session, AssetCreate(hostname="schema-host"))
    await db_session.commit()

    asset = (await test_client.get("/api/assets")).json()[0]
    required = {"id","hostname","criticality","environment","os_type","tags","ip_addresses"}
    assert required.issubset(set(asset.keys()))


@pytest.mark.asyncio
async def test_list_assets_ordered_criticality_desc(
    test_client: AsyncClient, db_session
):
    for tier, host in [(1,"h1"),(4,"h4"),(2,"h2"),(3,"h3")]:
        await create_asset(db_session, AssetCreate(hostname=host, criticality=tier))
    await db_session.commit()

    crits = [a["criticality"] for a in (await test_client.get("/api/assets")).json()]
    assert crits == sorted(crits, reverse=True)


@pytest.mark.asyncio
async def test_list_assets_filter_criticality(
    test_client: AsyncClient, db_session
):
    await create_asset(db_session, AssetCreate(hostname="h4", criticality=4))
    await create_asset(db_session, AssetCreate(hostname="h2", criticality=2))
    await db_session.commit()

    resp = await test_client.get("/api/assets?criticality=4")
    assert len(resp.json()) == 1
    assert resp.json()[0]["criticality"] == 4


@pytest.mark.asyncio
async def test_list_assets_filter_environment(
    test_client: AsyncClient, db_session
):
    await create_asset(db_session, AssetCreate(hostname="prod1", environment="production"))
    await create_asset(db_session, AssetCreate(hostname="dev1",  environment="development"))
    await db_session.commit()

    resp = await test_client.get("/api/assets?environment=production")
    assert len(resp.json()) == 1


@pytest.mark.asyncio
async def test_list_assets_filter_hostname_like(
    test_client: AsyncClient, db_session
):
    await create_asset(db_session, AssetCreate(hostname="web-server-01"))
    await create_asset(db_session, AssetCreate(hostname="db-server-01"))
    await create_asset(db_session, AssetCreate(hostname="cache-01"))
    await db_session.commit()

    resp = await test_client.get("/api/assets?hostname_like=server")
    assert len(resp.json()) == 2


# ── GET /api/assets/{id} ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_asset_by_id_returns_200(
    test_client: AsyncClient, db_session
):
    asset = await create_asset(db_session, AssetCreate(hostname="target-host"))
    await db_session.commit()

    resp = await test_client.get(f"/api/assets/{asset.id}")
    assert resp.status_code == 200
    assert resp.json()["hostname"] == "target-host"


@pytest.mark.asyncio
async def test_get_asset_by_id_404_on_missing(test_client: AsyncClient):
    resp = await test_client.get("/api/assets/nonexistent-id")
    assert resp.status_code == 404


# ── POST /api/assets ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_asset_returns_201(test_client: AsyncClient):
    resp = await test_client.post("/api/assets", json=_body())
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_create_asset_response_shape(test_client: AsyncClient):
    resp = await test_client.post("/api/assets", json=_body())
    data = resp.json()
    assert data["hostname"]    == "server01.corp"
    assert data["criticality"] == 2
    assert data["environment"] == "production"
    assert "id" in data


@pytest.mark.asyncio
async def test_create_asset_normalises_hostname(test_client: AsyncClient):
    resp = await test_client.post("/api/assets", json=_body(hostname="SERVER01.CORP"))
    assert resp.json()["hostname"] == "server01.corp"


@pytest.mark.asyncio
async def test_create_asset_invalid_criticality_returns_422(test_client: AsyncClient):
    resp = await test_client.post("/api/assets", json={**_body(), "criticality": 9})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_asset_invalid_environment_returns_422(test_client: AsyncClient):
    resp = await test_client.post("/api/assets", json={**_body(), "environment": "INVALID"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_asset_duplicate_hostname_returns_409(test_client: AsyncClient):
    await test_client.post("/api/assets", json=_body())
    resp = await test_client.post("/api/assets", json=_body())
    assert resp.status_code == 409


# ── POST /api/assets/upsert ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_upsert_creates_new_asset(test_client: AsyncClient):
    resp = await test_client.post("/api/assets/upsert", json=_body(hostname="new-host"))
    assert resp.status_code == 200
    assert resp.json()["hostname"] == "new-host"


@pytest.mark.asyncio
async def test_upsert_updates_existing_asset(test_client: AsyncClient):
    await test_client.post("/api/assets", json=_body(criticality=2))
    resp = await test_client.post("/api/assets/upsert", json=_body(criticality=4))
    assert resp.json()["criticality"] == 4


@pytest.mark.asyncio
async def test_upsert_does_not_create_duplicate(
    test_client: AsyncClient, db_session
):
    from sqlalchemy import text
    await test_client.post("/api/assets/upsert", json=_body())
    await test_client.post("/api/assets/upsert", json=_body(criticality=3))
    result = await db_session.execute(text("SELECT COUNT(*) FROM assets"))
    assert result.scalar() == 1


# ── PUT /api/assets/{id}/criticality ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_criticality_returns_200(
    test_client: AsyncClient, db_session
):
    asset = await create_asset(db_session, AssetCreate(hostname="crit-host"))
    await db_session.commit()

    resp = await test_client.put(
        f"/api/assets/{asset.id}/criticality",
        json={"criticality": 4},
    )
    assert resp.status_code == 200
    assert resp.json()["criticality"] == 4


@pytest.mark.asyncio
async def test_update_criticality_invalid_tier_returns_400(
    test_client: AsyncClient, db_session
):
    # NOTE: the request body is an untyped `dict` (no pydantic model) in
    # update_crit() (assets_router.py); range validation happens later in
    # update_criticality() (asset_service.py) which raises ValueError, and
    # the router maps that to HTTPException(400) — not a 422.
    asset = await create_asset(db_session, AssetCreate(hostname="crit2-host"))
    await db_session.commit()

    resp = await test_client.put(
        f"/api/assets/{asset.id}/criticality",
        json={"criticality": 99},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_update_criticality_404_on_missing(test_client: AsyncClient):
    resp = await test_client.put(
        "/api/assets/nonexistent/criticality",
        json={"criticality": 3},
    )
    assert resp.status_code == 404
