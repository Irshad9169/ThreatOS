"""
tests/integration/test_ti_route.py
──────────────────────────────────
Integration tests for /api/ti routes.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
import pytest_asyncio
from httpx import AsyncClient

from threatos.services.alert_service import persist_alert
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


def _alert_dict(entity_host="WIN-VICTIM", entity_ip=None, raw_match=None) -> dict:
    now = datetime.now(UTC)
    return {
        "id": str(uuid.uuid4()), "rule_id": "rule-123", "event_id": "evt-456",
        "technique_id": "T1059.001", "tactic": "execution", "severity": 7,
        "confidence": 0.85, "asset_criticality": 2, "risk_score": 52.5,
        "entity_host": entity_host, "entity_user": "alice",
        "entity_process": "powershell.exe", "entity_ip": entity_ip,
        "status": "open", "description": "Test alert",
        "raw_match": raw_match or {}, "created_at": now, "updated_at": now,
    }


# ── POST /api/ti/enrich ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_enrich_single_ioc_auto_detects_type(test_client: AsyncClient):
    resp = await test_client.post("/api/ti/enrich", json={"ioc_value": "malicious.example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ioc_type"] == "domain"

@pytest.mark.asyncio
async def test_enrich_single_ioc_undetectable_type_returns_400(test_client: AsyncClient):
    resp = await test_client.post("/api/ti/enrich", json={"ioc_value": "!!!not-an-ioc!!!"})
    assert resp.status_code == 400


# ── POST /api/ti/enrich-alert/{id} ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_enrich_alert_uses_entity_ip(test_client: AsyncClient, db_session):
    # Regression: ti_router.py used to build the alert_data dict with
    # getattr(alert, "src_ip", None) / "dst_ip" / "file_hash" — none of
    # which are real columns on the Alert model (only entity_ip and
    # raw_match exist) — so those getattr calls always silently returned
    # None and an alert's actual IP was never checked against any TI
    # source. Confirm entity_ip is now picked up.
    alert = await persist_alert(db_session, _alert_dict(entity_ip="1.2.3.4"))
    await db_session.commit()

    captured_iocs = []
    async def fake_enrich_ioc(db, ioc_type, ioc_value):
        captured_iocs.append((ioc_type, ioc_value))
        verdict = VERDICT_MALICIOUS if ioc_value == "1.2.3.4" else VERDICT_CLEAN
        return {"ioc_type": ioc_type, "ioc_value": ioc_value,
                "overall_verdict": verdict, "sources": {}}

    with patch("threatos.services.ti_service.enrich_ioc", fake_enrich_ioc):
        resp = await test_client.post(f"/api/ti/enrich-alert/{alert.id}")

    assert resp.status_code == 200
    assert ("ip", "1.2.3.4") in captured_iocs
    assert resp.json()["ti_verdict"] == VERDICT_MALICIOUS

@pytest.mark.asyncio
async def test_enrich_alert_result_actually_persists(test_client: AsyncClient, db_session):
    # Regression: threatos/models/alert.py never declared ti_enriched/
    # ti_verdict/ti_summary as mapped columns even though migration 007
    # added them to the real table — so `alert.ti_enriched = True` was
    # setting a plain, untracked Python attribute that SQLAlchemy's
    # unit-of-work never persisted. A GET immediately after the POST
    # (simulating a fresh request against a freshly-loaded row) is the
    # only way to catch that, as opposed to just checking the POST
    # response body, which reflects in-memory data regardless.
    from sqlalchemy import text

    alert = await persist_alert(db_session, _alert_dict(entity_ip="4.4.4.4"))
    await db_session.commit()

    async def fake_enrich_ioc(db, ioc_type, ioc_value):
        return {"ioc_type": ioc_type, "ioc_value": ioc_value,
                "overall_verdict": VERDICT_MALICIOUS, "sources": {}}

    with patch("threatos.services.ti_service.enrich_ioc", fake_enrich_ioc):
        resp = await test_client.post(f"/api/ti/enrich-alert/{alert.id}")
    assert resp.status_code == 200

    # Read the raw row rather than going through the ORM identity map, so
    # this genuinely proves the UPDATE was written, not just that the
    # in-memory object still reflects what the route set on it.
    row = (await db_session.execute(
        text("SELECT ti_enriched, ti_verdict, ti_summary FROM alerts WHERE id = :id"),
        {"id": alert.id},
    )).one()
    assert row.ti_enriched in (True, 1)
    assert row.ti_verdict == VERDICT_MALICIOUS
    assert row.ti_summary

@pytest.mark.asyncio
async def test_enrich_alert_uses_raw_match_for_extra_iocs(test_client: AsyncClient, db_session):
    # raw_match is passed through as raw_fields — extract_iocs_from_alert
    # checks raw_fields for file_hash/md5/sha256/domain/src_ip/dst_ip, so a
    # hash embedded in the rule match payload should now be picked up too.
    file_hash = "a" * 64
    alert = await persist_alert(db_session, _alert_dict(raw_match={"sha256": file_hash}))
    await db_session.commit()

    captured_iocs = []
    async def fake_enrich_ioc(db, ioc_type, ioc_value):
        captured_iocs.append((ioc_type, ioc_value))
        return {"ioc_type": ioc_type, "ioc_value": ioc_value,
                "overall_verdict": VERDICT_CLEAN, "sources": {}}

    with patch("threatos.services.ti_service.enrich_ioc", fake_enrich_ioc):
        resp = await test_client.post(f"/api/ti/enrich-alert/{alert.id}")

    assert resp.status_code == 200
    assert ("sha256", file_hash) in captured_iocs

@pytest.mark.asyncio
async def test_enrich_alert_404_on_missing(test_client: AsyncClient):
    resp = await test_client.post(f"/api/ti/enrich-alert/{uuid.uuid4()}")
    assert resp.status_code == 404

@pytest.mark.asyncio
async def test_enrich_alert_writes_audit_log_entry(test_client: AsyncClient, db_session):
    from sqlalchemy import select
    from threatos.models.audit_log import AuditLog
    from threatos.services.audit_service import Action, Resource

    alert = await persist_alert(db_session, _alert_dict(entity_ip="5.6.7.8"))
    await db_session.commit()

    async def fake_enrich_ioc(db, ioc_type, ioc_value):
        return {"ioc_type": ioc_type, "ioc_value": ioc_value,
                "overall_verdict": VERDICT_CLEAN, "sources": {}}

    with patch("threatos.services.ti_service.enrich_ioc", fake_enrich_ioc):
        resp = await test_client.post(f"/api/ti/enrich-alert/{alert.id}")
    assert resp.status_code == 200

    result = await db_session.execute(
        select(AuditLog).where(AuditLog.resource_id == alert.id))
    entry = result.scalar_one_or_none()
    assert entry is not None
    assert entry.action == Action.TI_ENRICHMENT
    assert entry.resource == Resource.ALERT


# ── GET /api/ti/alert/{id} ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_alert_enrichments_404_on_missing(test_client: AsyncClient):
    resp = await test_client.get(f"/api/ti/alert/{uuid.uuid4()}")
    assert resp.status_code == 404

@pytest.mark.asyncio
async def test_get_alert_enrichments_returns_cached_results(test_client: AsyncClient, db_session):
    alert = await persist_alert(db_session, _alert_dict(entity_ip="9.9.9.9"))
    await db_session.commit()

    from threatos.services.ti_service import save_enrichment
    await save_enrichment(db_session, "ip", "9.9.9.9", "abuseipdb", VERDICT_MALICIOUS, score=90)
    await db_session.commit()

    resp = await test_client.get(f"/api/ti/alert/{alert.id}")
    assert resp.status_code == 200
    data = resp.json()
    assert any(e["ioc_value"] == "9.9.9.9" and e["source"] == "abuseipdb"
               for e in data["enrichments"])


# ── POST /api/ti/enrich-open-alerts ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_enrich_open_alerts_only_processes_unenriched(test_client: AsyncClient, db_session):
    alert = await persist_alert(db_session, _alert_dict(entity_ip="1.1.1.1"))
    await db_session.commit()

    async def fake_enrich_ioc(db, ioc_type, ioc_value):
        return {"ioc_type": ioc_type, "ioc_value": ioc_value,
                "overall_verdict": VERDICT_CLEAN, "sources": {}}

    with patch("threatos.services.ti_service.enrich_ioc", fake_enrich_ioc):
        resp = await test_client.post("/api/ti/enrich-open-alerts?limit=10")

    assert resp.status_code == 200
    assert resp.json()["enriched"] == 1


# ── Stats & cache ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ti_stats_reflects_key_configuration(test_client: AsyncClient):
    resp = await test_client.get("/api/ti/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "virustotal_key" in data
    assert "abuseipdb_key" in data

@pytest.mark.asyncio
async def test_list_cache_filters_by_verdict(test_client: AsyncClient, db_session):
    from threatos.services.ti_service import save_enrichment
    await save_enrichment(db_session, "ip", "1.2.3.4", "virustotal", VERDICT_MALICIOUS)
    await save_enrichment(db_session, "domain", "clean.example", "virustotal", VERDICT_CLEAN)
    await db_session.commit()

    resp = await test_client.get("/api/ti/cache?verdict=malicious")
    assert resp.status_code == 200
    data = resp.json()
    assert all(e["verdict"] == "malicious" for e in data)
    assert any(e["ioc_value"] == "1.2.3.4" for e in data)

@pytest.mark.asyncio
async def test_cleanup_cache_deletes_expired(test_client: AsyncClient, db_session):
    from datetime import timedelta
    from threatos.models.ti_enrichment import TIEnrichment

    db_session.add(TIEnrichment(
        id=str(uuid.uuid4()), ioc_type="ip", ioc_value="8.8.8.8", source="virustotal",
        verdict=VERDICT_CLEAN, enriched_at=datetime.now(UTC) - timedelta(hours=48),
        expires_at=datetime.now(UTC) - timedelta(hours=24),
    ))
    await db_session.commit()

    resp = await test_client.delete("/api/ti/cache/cleanup")
    assert resp.status_code == 200
    assert resp.json()["deleted"] == 1
