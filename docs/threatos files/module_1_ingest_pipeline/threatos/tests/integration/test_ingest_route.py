"""
tests/integration/test_ingest_route.py
────────────────────────────────────────
Integration tests for POST /api/ingest/* routes.
Uses the real FastAPI app with a real SQLite DB.
Tests the full request → normalize → persist → response cycle.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import text


# ── POST /api/ingest/event ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ingest_single_json_event_returns_202(test_client: AsyncClient):
    resp = await test_client.post("/api/ingest/event", json={
        "log_source": "json",
        "payload": {"hostname": "srv01", "message": "test event"},
    })
    assert resp.status_code == 202


@pytest.mark.asyncio
async def test_ingest_single_event_response_has_required_fields(test_client: AsyncClient):
    resp = await test_client.post("/api/ingest/event", json={
        "log_source": "json",
        "payload": {"hostname": "srv01"},
    })
    data = resp.json()
    assert data["status"]   == "accepted"
    assert "event_id"  in data
    assert "hash"      in data


@pytest.mark.asyncio
async def test_ingest_event_is_persisted_to_db(
    test_client: AsyncClient,
    db_session,
):
    await test_client.post("/api/ingest/event", json={
        "log_source": "json",
        "payload": {"hostname": "persist-test-host"},
    })
    result = await db_session.execute(
        text("SELECT log_source, hash FROM raw_events LIMIT 1")
    )
    row = result.fetchone()
    assert row is not None
    assert row[0] == "json"      # log_source
    assert row[1] is not None    # hash was computed


@pytest.mark.asyncio
async def test_ingest_unknown_log_source_returns_400(test_client: AsyncClient):
    resp = await test_client.post("/api/ingest/event", json={
        "log_source": "unsupported_format",
        "payload": {"key": "value"},
    })
    assert resp.status_code == 400
    assert "Unsupported log_source" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_ingest_winlog_event_extracts_correct_fields(
    test_client: AsyncClient,
    db_session,
):
    resp = await test_client.post("/api/ingest/event", json={
        "log_source": "winlog",
        "payload": {
            "Computer": "WIN-DC01",
            "EventData": {
                "SubjectUserName": "alice",
                "Image": "powershell.exe",
                "CommandLine": "powershell -enc abc",
            },
        },
    })
    assert resp.status_code == 202

    # Verify the normalized column was written with correct values
    result = await db_session.execute(
        text("SELECT normalized FROM raw_events LIMIT 1")
    )
    row = result.fetchone()
    assert row is not None

    import json
    normalized = json.loads(row[0])
    assert normalized["host"]         == "WIN-DC01"
    assert normalized["user"]         == "alice"
    assert "powershell" in normalized["process"].lower()
    assert "-enc" in normalized["command_line"]


@pytest.mark.asyncio
async def test_ingest_cef_event_returns_202(test_client: AsyncClient):
    resp = await test_client.post("/api/ingest/event", json={
        "log_source": "cef",
        "payload": {
            "src": "192.168.1.1",
            "dst": "10.0.0.5",
            "dpt": "4444",
            "suser": "attacker",
        },
    })
    assert resp.status_code == 202


# ── POST /api/ingest/batch ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ingest_batch_returns_202(test_client: AsyncClient):
    resp = await test_client.post("/api/ingest/batch", json=[
        {"log_source": "json", "payload": {"hostname": f"host-{i}"}}
        for i in range(5)
    ])
    assert resp.status_code == 202


@pytest.mark.asyncio
async def test_ingest_batch_counts_are_correct(test_client: AsyncClient):
    resp = await test_client.post("/api/ingest/batch", json=[
        {"log_source": "json",    "payload": {"hostname": "good-host"}},
        {"log_source": "json",    "payload": {"hostname": "good-host-2"}},
        {"log_source": "INVALID", "payload": {"key": "value"}},
    ])
    data = resp.json()
    assert data["queued"] == 2
    assert data["failed"] == 1
    assert len(data["event_ids"]) == 2


@pytest.mark.asyncio
async def test_ingest_batch_all_events_persisted(
    test_client: AsyncClient,
    db_session,
):
    await test_client.post("/api/ingest/batch", json=[
        {"log_source": "json", "payload": {"hostname": f"batch-host-{i}"}}
        for i in range(3)
    ])
    result = await db_session.execute(text("SELECT COUNT(*) FROM raw_events"))
    count = result.scalar()
    assert count == 3


@pytest.mark.asyncio
async def test_ingest_batch_deduplicates_identical_events(
    test_client: AsyncClient,
    db_session,
):
    """Sending identical events twice should not double-insert them."""
    same_event = {"log_source": "json", "payload": {"hostname": "dedup-host", "process": {"name": "bash"}}}
    await test_client.post("/api/ingest/batch", json=[same_event, same_event, same_event])

    result = await db_session.execute(text("SELECT COUNT(*) FROM raw_events"))
    count = result.scalar()
    # All three have the same hash — ON CONFLICT DO NOTHING deduplicates
    assert count == 1


# ── POST /api/ingest/syslog ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ingest_syslog_rfc5424_returns_202(test_client: AsyncClient):
    line = "<14>1 2024-01-01T12:00:00Z server01 sshd 1234 - - Accepted publickey for alice"
    resp = await test_client.post(
        "/api/ingest/syslog",
        content=line,
        headers={"Content-Type": "text/plain"},
    )
    assert resp.status_code == 202


@pytest.mark.asyncio
async def test_ingest_syslog_response_shape(test_client: AsyncClient):
    line = "<14>1 2024-01-01T12:00:00Z server01 sshd 1234 - - test message"
    resp = await test_client.post(
        "/api/ingest/syslog",
        content=line,
        headers={"Content-Type": "text/plain"},
    )
    data = resp.json()
    assert data["status"]  == "accepted"
    assert data["event_id"] != ""
