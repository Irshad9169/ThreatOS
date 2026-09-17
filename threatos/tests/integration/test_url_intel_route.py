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
    async def fake_rdap(db, domain):
        return _fake_source("rdap", VERDICT_CLEAN, age_days=3650, registered_at="2015-01-01T00:00:00Z")

    with patch("threatos.services.url_intel_service.enrich_url_virustotal", fake_vt), \
         patch("threatos.services.url_intel_service.enrich_url_urlscan", fake_urlscan), \
         patch("threatos.services.url_intel_service.enrich_url_spamhaus", fake_spamhaus), \
         patch("threatos.services.url_intel_service.enrich_url_urlhaus", fake_urlhaus), \
         patch("threatos.services.url_intel_service.enrich_url_domain_age", fake_rdap):
        resp = await test_client.post(
            "/api/url-intel/investigate", json={"url": "https://phish.example/login"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["overall_verdict"] == VERDICT_MALICIOUS
    assert data["domain"] == "phish.example"
    assert "VERDICT: MALICIOUS" in data["report_text"]
    assert set(data["sources"]) == {"virustotal", "urlscan", "spamhaus", "urlhaus", "rdap"}


@pytest.mark.asyncio
async def test_stats_reports_key_configuration(test_client: AsyncClient):
    resp = await test_client.get("/api/url-intel/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "urlscan_key" in data
    assert "urlhaus_key" in data
    assert "total_cached" in data


@pytest.mark.asyncio
async def test_history_lists_past_investigation_without_rescanning(test_client: AsyncClient):
    async def fake_vt(db, url):
        return _fake_source("virustotal", VERDICT_MALICIOUS, malicious_engines=5, total_engines=90)
    async def fake_urlscan(db, url, domain):
        return _fake_source("urlscan", VERDICT_CLEAN)
    async def fake_spamhaus(db, domain):
        return _fake_source("spamhaus", VERDICT_CLEAN, reason="not listed")
    async def fake_urlhaus(db, url):
        return _fake_source("urlhaus", VERDICT_NO_KEY, message="no key configured")
    async def fake_rdap(db, domain):
        return _fake_source("rdap", VERDICT_CLEAN, age_days=3650, registered_at="2015-01-01T00:00:00Z")

    with patch("threatos.services.url_intel_service.enrich_url_virustotal", fake_vt), \
         patch("threatos.services.url_intel_service.enrich_url_urlscan", fake_urlscan), \
         patch("threatos.services.url_intel_service.enrich_url_spamhaus", fake_spamhaus), \
         patch("threatos.services.url_intel_service.enrich_url_urlhaus", fake_urlhaus), \
         patch("threatos.services.url_intel_service.enrich_url_domain_age", fake_rdap):
        investigate_resp = await test_client.post(
            "/api/url-intel/investigate", json={"url": "https://history-test.example/x"})
    investigation_id = investigate_resp.json()["id"]

    history_resp = await test_client.get("/api/url-intel/history")
    assert history_resp.status_code == 200
    entries = history_resp.json()
    assert any(e["id"] == investigation_id for e in entries)
    match = next(e for e in entries if e["id"] == investigation_id)
    assert match["domain"] == "history-test.example"
    assert "VERDICT: MALICIOUS" in match["report_text"]

    detail_resp = await test_client.get(f"/api/url-intel/history/{investigation_id}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["report_text"] == match["report_text"]

@pytest.mark.asyncio
async def test_history_detail_404_on_missing(test_client: AsyncClient):
    resp = await test_client.get("/api/url-intel/history/not-a-real-id")
    assert resp.status_code == 404
