"""Integration tests for /api/settings routes."""
from __future__ import annotations
import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import AsyncClient

from threatos.services import settings_service, url_intel_service


@pytest.fixture(autouse=True)
def _isolate_env(tmp_path, monkeypatch):
    monkeypatch.setattr(settings_service, "_ENV_PATH", tmp_path / ".env")
    monkeypatch.setattr(url_intel_service, "URLSCAN_API_KEY", url_intel_service.URLSCAN_API_KEY)
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)


@pytest_asyncio.fixture
async def _as_admin(db_session):
    from threatos.core.dependencies import get_current_user
    from threatos.main import app
    from threatos.models.user import User

    user = User(
        id=str(uuid.uuid4()), username=f"admin-{uuid.uuid4().hex[:8]}",
        email=f"admin-{uuid.uuid4().hex[:8]}@example.com",
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


@pytest_asyncio.fixture
async def _as_engineer(db_session):
    from threatos.core.dependencies import get_current_user
    from threatos.main import app
    from threatos.models.user import User

    user = User(
        id=str(uuid.uuid4()), username=f"eng-{uuid.uuid4().hex[:8]}",
        email=f"eng-{uuid.uuid4().hex[:8]}@example.com",
        password_hash="not-a-real-hash", role="engineer", is_active=True,
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    await db_session.flush()

    async def _override():
        return user

    app.dependency_overrides[get_current_user] = _override
    yield user
    app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.asyncio
async def test_admin_can_view_key_status(test_client: AsyncClient, _as_admin):
    resp = await test_client.get("/api/settings/api-keys")
    assert resp.status_code == 200
    assert "URLSCAN_API_KEY" in resp.json()

@pytest.mark.asyncio
async def test_non_admin_forbidden(test_client: AsyncClient, _as_engineer):
    resp = await test_client.get("/api/settings/api-keys")
    assert resp.status_code == 403

@pytest.mark.asyncio
async def test_admin_can_set_key_and_it_takes_effect(test_client: AsyncClient, _as_admin):
    resp = await test_client.post("/api/settings/api-keys",
        json={"key_name": "URLSCAN_API_KEY", "value": "brand-new-key"})
    assert resp.status_code == 200
    assert resp.json() == {"key_name": "URLSCAN_API_KEY", "configured": True}
    assert url_intel_service.URLSCAN_API_KEY == "brand-new-key"

    status_resp = await test_client.get("/api/settings/api-keys")
    assert status_resp.json()["URLSCAN_API_KEY"] is True

@pytest.mark.asyncio
async def test_rejects_unmanaged_key_name(test_client: AsyncClient, _as_admin):
    resp = await test_client.post("/api/settings/api-keys",
        json={"key_name": "THREATOS_ADMIN_PASSWORD", "value": "x"})
    assert resp.status_code == 400

@pytest.mark.asyncio
async def test_non_admin_cannot_set_key(test_client: AsyncClient, _as_engineer):
    resp = await test_client.post("/api/settings/api-keys",
        json={"key_name": "URLSCAN_API_KEY", "value": "x"})
    assert resp.status_code == 403
