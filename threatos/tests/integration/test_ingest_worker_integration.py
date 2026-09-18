"""
tests/integration/test_ingest_worker_integration.py
─────────────────────────────────────────────────────
End-to-end integration tests for the ingest worker pipeline.

Proves (in a way unit tests cannot):
  - stream message → process_batch → real alert rows in SQLite DB
  - log_source filtering, zero-match events, mixed batches
  - XACK clears the PEL after processing
  - asset criticality flows into risk_score and is persisted

No real Redis or PostgreSQL required — fakeredis + SQLite in-memory.
Oracle Linux 8: identical test command.
"""
from __future__ import annotations

import contextlib
import json
import uuid
from unittest.mock import patch

import fakeredis.aioredis as fake_aioredis
import pytest
from sqlalchemy import text

from threatos.detection.rule_engine import clear_rules, load_rules_into_engine
from threatos.workers.ingest_worker import (
    _CriticalityCache,
    _process_batch,
)

STREAM = "threatos:events:normalized"
GROUP  = "detection-workers"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_engine():
    clear_rules()
    yield
    clear_rules()


@pytest.fixture
async def redis_with_group():
    r = fake_aioredis.FakeRedis(decode_responses=True)
    await r.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
    yield r
    await r.aclose()


@pytest.fixture
def cache(redis_with_group):
    return _CriticalityCache(redis_with_group)


def _fields(
    log_source: str = "winlog",
    process:    str = "powershell.exe",
    cmdline:    str = "powershell.exe -EncodedCommand SQBFAFgA",
    host:       str = "WIN-VICTIM",
) -> dict:
    return {
        "event_id":    str(uuid.uuid4()),
        "log_source":  log_source,
        "host":        host,
        "process":     process,
        "command_line":cmdline,
        "raw_fields":  json.dumps({"process": process, "command_line": cmdline}),
    }


def _load_ps_rule(log_sources: list | None = None) -> None:
    load_rules_into_engine([{
        "id":           f"rule-{uuid.uuid4()}",
        "name":         "PowerShell encoded command",
        "technique_id": "T1059.001",
        "tactic":       "execution",
        "log_sources":  log_sources or [],
        "severity":     7,
        "confidence":   0.85,
        "detection_ast":{
            "type": "and",
            "children": [
                {"type":"field_match","field":"process",
                 "operator":"contains","value":"powershell"},
                {"type":"field_match","field":"command_line",
                 "operator":"contains","value":"-EncodedCommand"},
            ],
        },
        "tags": [],
    }])


async def _push_and_read(redis, fields: dict, count: int = 10):
    await redis.xadd(STREAM, fields)
    raw = await redis.xreadgroup(GROUP, "test-worker",
                                  streams={STREAM: ">"}, count=count)
    return raw[0][1]


def _make_db_ctx(db_session):
    """Return a proper async context manager that yields the test session."""
    @contextlib.asynccontextmanager
    async def _ctx():
        yield db_session
        await db_session.flush()
    return _ctx


# ── Tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_matching_event_creates_alert_in_db(
    redis_with_group, cache, db_session
):
    """Happy path: matching event → alert row in DB."""
    _load_ps_rule()
    await cache.set("WIN-VICTIM", 2)
    messages = await _push_and_read(redis_with_group, _fields())

    with patch("threatos.workers.ingest_worker.get_db_context",
               _make_db_ctx(db_session)):
        alerts_n, events_n = await _process_batch(redis_with_group, messages, cache)

    assert events_n == 1
    assert alerts_n == 1
    row = (await db_session.execute(text("SELECT COUNT(*) FROM alerts"))).scalar()
    assert row == 1


@pytest.mark.asyncio
async def test_non_matching_event_creates_no_alert(
    redis_with_group, cache, db_session
):
    """Benign event matches no rule → zero alerts."""
    _load_ps_rule()
    await cache.set("WIN-VICTIM", 2)
    benign = _fields(process="notepad.exe", cmdline="notepad.exe readme.txt")
    messages = await _push_and_read(redis_with_group, benign)

    with patch("threatos.workers.ingest_worker.get_db_context",
               _make_db_ctx(db_session)):
        alerts_n, events_n = await _process_batch(redis_with_group, messages, cache)

    assert events_n == 1
    assert alerts_n == 0
    row = (await db_session.execute(text("SELECT COUNT(*) FROM alerts"))).scalar()
    assert row == 0


@pytest.mark.asyncio
async def test_batch_of_mixed_events(redis_with_group, cache, db_session):
    """3 events: 2 match, 1 benign → 2 alerts."""
    _load_ps_rule()
    for host in ("WIN-A", "WIN-B", "WIN-C"):
        await cache.set(host, 2)

    for proc, cmdline, host in [
        ("powershell.exe", "powershell -EncodedCommand abc", "WIN-A"),
        ("notepad.exe",    "notepad.exe doc.txt",            "WIN-B"),
        ("powershell.exe", "powershell -EncodedCommand xyz", "WIN-C"),
    ]:
        await redis_with_group.xadd(STREAM, _fields(process=proc, cmdline=cmdline, host=host))

    raw      = await redis_with_group.xreadgroup(GROUP, "test-worker",
                                                  streams={STREAM: ">"}, count=10)
    messages = raw[0][1]

    with patch("threatos.workers.ingest_worker.get_db_context",
               _make_db_ctx(db_session)):
        alerts_n, events_n = await _process_batch(redis_with_group, messages, cache)

    assert events_n == 3
    assert alerts_n == 2
    row = (await db_session.execute(text("SELECT COUNT(*) FROM alerts"))).scalar()
    assert row == 2


@pytest.mark.asyncio
async def test_log_source_filter_respected(redis_with_group, cache, db_session):
    """Rule scoped to 'cef' must not fire on 'winlog' source."""
    _load_ps_rule(log_sources=["cef"])
    await cache.set("WIN-VICTIM", 2)
    messages = await _push_and_read(redis_with_group, _fields(log_source="winlog"))

    with patch("threatos.workers.ingest_worker.get_db_context",
               _make_db_ctx(db_session)):
        alerts_n, _ = await _process_batch(redis_with_group, messages, cache)

    assert alerts_n == 0


@pytest.mark.asyncio
async def test_alert_risk_score_reflects_criticality(
    redis_with_group, cache, db_session
):
    """Tier-4 asset produces elevated risk_score stored in the alert row."""
    _load_ps_rule()
    await cache.set("critical-host", 4)
    messages = await _push_and_read(redis_with_group, _fields(host="critical-host"))

    with patch("threatos.workers.ingest_worker.get_db_context",
               _make_db_ctx(db_session)):
        await _process_batch(redis_with_group, messages, cache)

    result = await db_session.execute(
        text("SELECT risk_score, asset_criticality FROM alerts LIMIT 1")
    )
    row = result.fetchone()
    assert row is not None
    assert row[1] == 4          # asset_criticality column persisted correctly
    assert row[0] > 50          # risk_score is high for tier-4 asset


@pytest.mark.asyncio
async def test_all_messages_acked_after_batch(redis_with_group, cache, db_session):
    """PEL is empty after successful processing — no duplicate delivery."""
    _load_ps_rule()
    await cache.set("WIN-VICTIM", 2)
    for _ in range(3):
        await redis_with_group.xadd(STREAM, _fields())
    raw      = await redis_with_group.xreadgroup(GROUP, "test-worker",
                                                  streams={STREAM: ">"}, count=10)
    messages = raw[0][1]

    with patch("threatos.workers.ingest_worker.get_db_context",
               _make_db_ctx(db_session)):
        await _process_batch(redis_with_group, messages, cache)

    pending = await redis_with_group.xpending(STREAM, GROUP)
    assert pending["pending"] == 0


@pytest.mark.asyncio
async def test_empty_stream_produces_no_alerts(redis_with_group, cache, db_session):
    """Empty message list → no DB writes."""
    with patch("threatos.workers.ingest_worker.get_db_context",
               _make_db_ctx(db_session)):
        alerts_n, events_n = await _process_batch(redis_with_group, [], cache)

    assert alerts_n == 0
    assert events_n == 0


@pytest.mark.asyncio
async def test_burst_of_duplicate_events_in_one_batch_suppressed(
    redis_with_group, cache, db_session
):
    """Regression: suppression previously only caught duplicates across
    separate batches, never within a single batch, because
    _check_suppression queried the DB before any of the batch's own
    alerts had been persisted. A burst of 5 identical rule+host events
    landing in the same batch (the exact alert-storm scenario
    suppression exists for) must collapse to a single alert."""
    _load_ps_rule()
    await cache.set("WIN-VICTIM", 2)
    for _ in range(5):
        await redis_with_group.xadd(STREAM, _fields())
    raw      = await redis_with_group.xreadgroup(GROUP, "test-worker",
                                                  streams={STREAM: ">"}, count=10)
    messages = raw[0][1]

    with patch("threatos.workers.ingest_worker.get_db_context",
               _make_db_ctx(db_session)):
        alerts_n, events_n = await _process_batch(redis_with_group, messages, cache)

    assert events_n == 5
    assert alerts_n == 1
    row = (await db_session.execute(text("SELECT COUNT(*) FROM alerts"))).scalar()
    assert row == 1
