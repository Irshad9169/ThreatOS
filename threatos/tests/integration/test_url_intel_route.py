"""Integration tests for /api/url-intel routes."""
from __future__ import annotations
import uuid
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
import pytest_asyncio
from httpx import AsyncClient

from threatos.services.ti_service import VERDICT_CLEAN, VERDICT_MALICIOUS, VERDICT_NO_KEY


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


def _fake_source(source: str, verdict: str, **extra) -> dict:
    return {"source": source, "verdict": verdict, **extra}


@pytest.mark.asyncio
async def test_investigate_rejects_invalid_url(test_client: AsyncClient):
    resp = await test_client.post("/api/url-intel/investigate", json={"url": "not-a-url"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_investigate_returns_report_and_verdict(test_client: AsyncClient):
    async def fake_vt(db, url):
        return _fake_source("virustotal", VERDICT_MALICIOUS, malicious_engines=5, total_engines=90)
    async def fake_urlscan(db, url, domain):
        return _fake_source("urlscan", VERDICT_MALICIOUS, score=90)
    async def fake_spamhaus(db, domain):
        return _fake_source("spamhaus", VERDICT_CLEAN, reason="not listed")
    async def fake_urlhaus(db, url):
        return _fake_source("urlhaus", VERDICT_NO_KEY, message="no key configured")

    with patch("threatos.services.url_intel_service.enrich_url_virustotal", fake_vt), \
         patch("threatos.services.url_intel_service.enrich_url_urlscan", fake_urlscan), \
         patch("threatos.services.url_intel_service.enrich_url_spamhaus", fake_spamhaus), \
         patch("threatos.services.url_intel_service.enrich_url_urlhaus", fake_urlhaus):
        resp = await test_client.post(
            "/api/url-intel/investigate", json={"url": "https://phish.example/login"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["overall_verdict"] == VERDICT_MALICIOUS
    assert data["domain"] == "phish.example"
    assert "VERDICT: MALICIOUS" in data["report_text"]
    assert set(data["sources"]) == {"virustotal", "urlscan", "spamhaus", "urlhaus"}


@pytest.mark.asyncio
async def test_stats_reports_key_configuration(test_client: AsyncClient):
    resp = await test_client.get("/api/url-intel/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "urlscan_key" in data
    assert "urlhaus_key" in data
    assert "total_cached" in data
