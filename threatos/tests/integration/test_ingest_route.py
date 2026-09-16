"""
tests/integration/test_ingest_route.py
────────────────────────────────────────
Integration tests for POST /api/ingest/* routes.
Uses the real FastAPI app with a real SQLite DB.
Tests the full request → normalize → persist → response cycle.

NOTE ON DRIFT FROM THE HISTORICAL API:
Current EventIn (threatos/api/routers/ingest_router.py) is
`{"payload": dict, "fmt": str = "json"}` — there is no top-level
"log_source" request field any more (FastAPI/pydantic silently drops it as
an unrecognised extra field). All three POST routes now require an
authenticated user with the "ingest"/"engineer"/"admin" role
(Depends(require_ingest)), and return 201 (not 202) on success.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import text


# ── Auth: all /api/ingest routes require the "ingest"/"engineer"/"admin"
# role (see threatos/api/routers/ingest_router.py — Depends(require_ingest)).
# Bypass real JWT/API-key auth by overriding the dependency with a real,
# session-persisted admin user (admin satisfies require_ingest too).

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


# ── POST /api/ingest/event ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ingest_single_json_event_returns_201(test_client: AsyncClient):
    resp = await test_client.post("/api/ingest/event", json={
        "fmt": "json",
        "payload": {"hostname": "srv01", "message": "test event"},
    })
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_ingest_single_event_response_has_required_fields(test_client: AsyncClient):
    resp = await test_client.post("/api/ingest/event", json={
        "fmt": "json",
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
        "fmt": "json",
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
async def test_ingest_duplicate_event_returns_duplicate_status(
    test_client: AsyncClient, db_session,
):
    """Same payload sent twice → same content hash → second is a duplicate,
    not a second insert (RawEvent.hash has a UniqueConstraint — see
    threatos/models/raw_event.py)."""
    body = {"fmt": "json", "payload": {"hostname": "dup-host", "message": "same"}}
    first  = await test_client.post("/api/ingest/event", json=body)
    second = await test_client.post("/api/ingest/event", json=body)

    assert first.json()["status"]  == "accepted"
    assert second.json()["status"] == "duplicate"

    count = (await db_session.execute(
        text("SELECT COUNT(*) FROM raw_events")
    )).scalar()
    assert count == 1


@pytest.mark.asyncio
async def test_ingest_unrecognised_fmt_is_accepted_not_rejected(test_client: AsyncClient):
    # NOTE: unlike the historical API, validate_log_source() (core/sanitiser.py)
    # never raises for an unrecognised `fmt` — it just normalises it to
    # "custom" — and ingest_event() (ingest_router.py) has no branch that
    # returns 400 "Unsupported log_source" any more. An unknown fmt is
    # accepted and falls through to normalize_json().
    resp = await test_client.post("/api/ingest/event", json={
        "fmt": "unsupported_format",
        "payload": {"key": "value"},
    })
    assert resp.status_code == 201
    assert resp.json()["status"] == "accepted"


@pytest.mark.asyncio
async def test_ingest_winlog_event_extracts_correct_fields(
    test_client: AsyncClient,
    db_session,
):
    # NOTE: normalize_winlog() (threatos/ingestion/normalizer.py) reads the
    # outer host from raw["host"]/raw["computer_name"] (snake_case) and the
    # nested block from raw["event_data"] (snake_case key) — but the fields
    # *inside* that block keep their original Windows Event Log PascalCase
    # names (SubjectUserName, NewProcessName, CommandLine). The historical
    # payload ("Computer"/"EventData" outer keys) doesn't match any of these
    # and silently normalizes to all-None fields.
    resp = await test_client.post("/api/ingest/event", json={
        "fmt": "winlog",
        "payload": {
            "computer_name": "WIN-DC01",
            "event_data": {
                "SubjectUserName": "alice",
                "NewProcessName": "powershell.exe",
                "CommandLine": "powershell -enc abc",
            },
        },
    })
    assert resp.status_code == 201

    # Verify the normalized column was written with correct values
    result = await db_session.execute(
        text("SELECT normalized FROM raw_events LIMIT 1")
    )
    row = result.fetchone()
    assert row is not None

    normalized = json.loads(row[0])
    assert normalized["host"]         == "WIN-DC01"
    assert normalized["user"]         == "alice"
    assert "powershell" in normalized["process"].lower()
    assert "-enc" in normalized["command_line"]


@pytest.mark.asyncio
async def test_ingest_cef_event_returns_201(test_client: AsyncClient):
    # NOTE: normalize_cef() (normalizer.py) expects a raw pipe-delimited CEF
    # line (str). normalize_event() only ever calls it with a real string
    # when `raw` is already a str — but ingest_event() always hands it a
    # JSON `payload` dict, so it falls back to `json.dumps(raw)`, which has
    # no "|" separators. The event is still accepted (no crash), it just
    # never extracts any CEF extension fields — this route effectively can't
    # ingest CEF the way it can syslog (which reads a raw line from
    # payload["message"]). Flagged in the test-porting report as a
    # suspected production gap; not skipped since the historical test never
    # asserted the extracted fields either — only that ingestion doesn't
    # error out.
    resp = await test_client.post("/api/ingest/event", json={
        "fmt": "cef",
        "payload": {
            "src": "192.168.1.1",
            "dst": "10.0.0.5",
            "dpt": "4444",
            "suser": "attacker",
        },
    })
    assert resp.status_code == 201


# ── POST /api/ingest/batch ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ingest_batch_returns_201(test_client: AsyncClient):
    resp = await test_client.post("/api/ingest/batch", json=[
        {"fmt": "json", "payload": {"hostname": f"host-{i}"}}
        for i in range(5)
    ])
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_ingest_batch_counts_are_correct(test_client: AsyncClient):
    # NOTE: ingest_batch() (ingest_router.py) no longer rejects events for
    # an "invalid" fmt/log_source (see test_ingest_unrecognised_fmt_is_
    # accepted_not_rejected above) — the only way an item lands in
    # `rejected` now is check_payload_size() failing (> MAX_PAYLOAD_BYTES =
    # 64KB, core/sanitiser.py), and the only way it lands in `duplicates` is
    # a repeated content hash within/against already-ingested events.
    oversized = {"blob": "x" * 70_000}   # > MAX_PAYLOAD_BYTES
    resp = await test_client.post("/api/ingest/batch", json=[
        {"fmt": "json", "payload": {"hostname": "good-host"}},
        {"fmt": "json", "payload": {"hostname": "good-host"}},  # duplicate of the row above
        {"fmt": "json", "payload": oversized},                  # too large -> rejected
    ])
    data = resp.json()
    assert data["accepted"]   == 1
    assert data["duplicates"] == 1
    assert data["rejected"]   == 1


@pytest.mark.asyncio
async def test_ingest_batch_all_events_persisted(
    test_client: AsyncClient,
    db_session,
):
    await test_client.post("/api/ingest/batch", json=[
        {"fmt": "json", "payload": {"hostname": f"batch-host-{i}"}}
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
    same_event = {"fmt": "json", "payload": {"hostname": "dedup-host", "process": {"name": "bash"}}}
    resp = await test_client.post("/api/ingest/batch", json=[same_event, same_event, same_event])

    data = resp.json()
    assert data["accepted"]   == 1
    assert data["duplicates"] == 2

    result = await db_session.execute(text("SELECT COUNT(*) FROM raw_events"))
    count = result.scalar()
    assert count == 1


# ── POST /api/ingest/syslog ───────────────────────────────────────────────────
# NOTE: ingest_syslog() (ingest_router.py) takes a JSON `body: dict`, not a
# raw text/plain request body. normalize_event(..., "syslog") only treats
# `raw` as the literal syslog line when it's already a str; for a dict body
# it reads `raw.get("message", "")` (normalizer.py). So the RFC5424/BSD line
# must be sent as JSON: {"message": "<the raw line>"}.

@pytest.mark.asyncio
async def test_ingest_syslog_rfc5424_returns_201(test_client: AsyncClient):
    line = "<14>1 2024-01-01T12:00:00Z server01 sshd 1234 - - Accepted publickey for alice"
    resp = await test_client.post("/api/ingest/syslog", json={"message": line})
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_ingest_syslog_response_shape(test_client: AsyncClient):
    line = "<14>1 2024-01-01T12:00:00Z server01 sshd 1234 - - test message"
    resp = await test_client.post("/api/ingest/syslog", json={"message": line})
    data = resp.json()
    assert data["status"]   == "accepted"
    assert data["event_id"] != ""
