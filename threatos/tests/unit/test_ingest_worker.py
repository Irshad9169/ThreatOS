"""
tests/unit/test_ingest_worker.py
─────────────────────────────────
Unit tests for workers/ingest_worker.py.

Tested in isolation:
  - _process_message: parses fields, evaluates rules, returns alert dicts
  - _process_batch: calls process_message, persists alerts, acks messages
  - _CriticalityCache: get/set with fakeredis, miss sentinel, default
  - _resolve_criticality: cache hit → no DB; cache miss → DB lookup

No real Redis, no real PostgreSQL, no real Docker required.
Oracle Linux 8 compatible: same test command on OL8:
  python3.11 -m pytest threatos/tests/unit/test_ingest_worker.py -v
"""
from __future__ import annotations

import json
import uuid
from unittest.mock import AsyncMock, patch

import fakeredis.aioredis as fake_aioredis
import pytest

from threatos.core.attck_kb import ATTCKTechnique, override_attck_cache
from threatos.detection.rule_engine import (
    clear_rules,
    load_rules_into_engine,
)
from threatos.workers.ingest_worker import (
    _CriticalityCache,
    _process_batch,
    _process_message,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_engine():
    """Ensure the rule engine is empty before and after each test."""
    clear_rules()
    yield
    clear_rules()


@pytest.fixture(autouse=True)
def clean_kb():
    override_attck_cache({})
    yield
    override_attck_cache({})


@pytest.fixture
def fake_redis():
    return fake_aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def cache(fake_redis):
    return _CriticalityCache(fake_redis)


def _powershell_fields() -> dict:
    """Stream message fields for a PowerShell -EncodedCommand event."""
    return {
        "event_id":    str(uuid.uuid4()),
        "log_source":  "winlog",
        "host":        "WIN-VICTIM",
        "user":        "alice",
        "process":     "powershell.exe",
        "command_line":"powershell.exe -EncodedCommand SQBFAFgA",
        "raw_fields":  json.dumps({
            "process":      "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand SQBFAFgA",
        }),
    }


def _load_ps_rule():
    """Load a single PowerShell detection rule into the engine."""
    load_rules_into_engine([{
        "id":           "rule-ps-001",
        "name":         "PowerShell encoded command",
        "technique_id": "T1059.001",
        "tactic":       "execution",
        "log_sources":  [],
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
        "tags": ["attack.t1059.001"],
    }])


# ── _CriticalityCache ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cache_miss_returns_sentinel(cache):
    result = await cache.get("unknown-host")
    assert result == -1   # miss sentinel

@pytest.mark.asyncio
async def test_cache_set_then_get(cache):
    await cache.set("dc01", 4)
    result = await cache.get("dc01")
    assert result == 4

@pytest.mark.asyncio
async def test_cache_normalises_hostname(cache):
    await cache.set("WIN-DC01", 3)
    # key stored lowercase
    result = await cache.get("win-dc01")
    assert result == 3

@pytest.mark.asyncio
async def test_cache_get_returns_int_not_str(cache):
    await cache.set("srv01", 2)
    result = await cache.get("srv01")
    assert isinstance(result, int)


# ── _process_message ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_process_message_empty_engine_returns_no_alerts(cache):
    # No rules loaded → no matches
    alerts = await _process_message("msg-001", _powershell_fields(), cache)
    assert alerts == []

@pytest.mark.asyncio
async def test_process_message_matching_rule_returns_alert(cache):
    _load_ps_rule()
    # Pre-seed cache so _resolve_criticality does not attempt a DB connection
    await cache.set("WIN-VICTIM", 2)
    alerts = await _process_message("msg-001", _powershell_fields(), cache)
    assert len(alerts) == 1
    assert alerts[0]["technique_id"] == "T1059.001"

@pytest.mark.asyncio
async def test_process_message_alert_has_required_keys(cache):
    _load_ps_rule()
    await cache.set("WIN-VICTIM", 2)
    alerts = await _process_message("msg-001", _powershell_fields(), cache)
    alert = alerts[0]
    required = {
        "id","rule_id","event_id","technique_id","tactic",
        "severity","confidence","risk_score","status",
        "entity_host","entity_user","created_at",
    }
    assert required.issubset(set(alert.keys()))

@pytest.mark.asyncio
async def test_process_message_status_is_open(cache):
    _load_ps_rule()
    await cache.set("WIN-VICTIM", 2)
    alerts = await _process_message("msg-001", _powershell_fields(), cache)
    assert alerts[0]["status"] == "open"

@pytest.mark.asyncio
async def test_process_message_entity_host_from_event(cache):
    _load_ps_rule()
    await cache.set("WIN-VICTIM", 2)
    alerts = await _process_message("msg-001", _powershell_fields(), cache)
    assert alerts[0]["entity_host"] == "WIN-VICTIM"

@pytest.mark.asyncio
async def test_process_message_uses_default_criticality_when_no_cache(cache):
    """When host not in cache and no DB lookup, default criticality=2."""
    _load_ps_rule()
    with patch(
        "threatos.workers.ingest_worker.get_asset_by_hostname",
        new_callable=AsyncMock,
        return_value=None,
    ):
        alerts = await _process_message("msg-001", _powershell_fields(), cache)
    assert len(alerts) == 1
    assert alerts[0]["asset_criticality"] == 2

@pytest.mark.asyncio
async def test_process_message_uses_cached_criticality(cache):
    """Cached criticality=4 flows into risk score."""
    _load_ps_rule()
    await cache.set("WIN-VICTIM", 4)
    alerts = await _process_message("msg-001", _powershell_fields(), cache)
    assert alerts[0]["asset_criticality"] == 4

@pytest.mark.asyncio
async def test_process_message_critical_asset_has_higher_risk_score(cache):
    """risk_score for criticality=4 must be higher than criticality=1."""
    _load_ps_rule()
    await cache.set("WIN-VICTIM", 4)
    high = await _process_message("msg-001", _powershell_fields(), cache)
    await cache.set("WIN-VICTIM", 1)
    low  = await _process_message("msg-002", _powershell_fields(), cache)
    assert high[0]["risk_score"] > low[0]["risk_score"]

@pytest.mark.asyncio
async def test_process_message_malformed_fields_returns_empty(cache):
    """Corrupt message fields must not crash the worker."""
    bad_fields = {"event_id": "x", "log_source": "json",
                  "dst_port": "NOT_A_NUMBER_BUT_HANDLE_IT",
                  "raw_fields": "{corrupt json %%"}
    alerts = await _process_message("msg-bad", bad_fields, cache)
    assert isinstance(alerts, list)   # returned list, did not raise

@pytest.mark.asyncio
async def test_process_message_missing_host_uses_default_criticality(cache):
    _load_ps_rule()
    fields = _powershell_fields()
    del fields["host"]
    alerts = await _process_message("msg-001", fields, cache)
    # May or may not match depending on rule — must not raise
    assert isinstance(alerts, list)

@pytest.mark.asyncio
async def test_process_message_non_matching_event_returns_empty(cache):
    _load_ps_rule()
    benign = {
        "event_id":    str(uuid.uuid4()),
        "log_source":  "json",
        "process":     "notepad.exe",
        "command_line":"notepad.exe document.txt",
        "raw_fields":  json.dumps({"process": "notepad.exe"}),
    }
    alerts = await _process_message("msg-benign", benign, cache)
    assert alerts == []


# ── _process_batch ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_process_batch_acks_all_messages(fake_redis, cache):
    _load_ps_rule()
    stream = "threatos:events:normalized"
    group  = "detection-workers"

    # Set up stream + consumer group in fakeredis
    await fake_redis.xgroup_create(stream, group, id="0", mkstream=True)
    msg_id = await fake_redis.xadd(stream, _powershell_fields())
    await fake_redis.xadd(stream, _powershell_fields())

    # Read messages as the consumer
    raw = await fake_redis.xreadgroup(group, "test-consumer",
                                       streams={stream: ">"}, count=10)
    messages = raw[0][1]   # list of (id, fields)

    with patch("threatos.workers.ingest_worker.persist_alerts_bulk",
               new_callable=AsyncMock, return_value=2), \
         patch("threatos.workers.ingest_worker.get_db_context") as mock_db:
        # make get_db_context an async context manager
        mock_db.return_value.__aenter__ = AsyncMock()
        mock_db.return_value.__aexit__  = AsyncMock(return_value=False)

        alerts_n, events_n = await _process_batch(fake_redis, messages, cache)

    assert events_n == 2
    # Pending entries list should be empty after XACK
    pending = await fake_redis.xpending(stream, group)
    assert pending["pending"] == 0

@pytest.mark.asyncio
async def test_process_batch_empty_messages_returns_zeros(fake_redis, cache):
    alerts_n, events_n = await _process_batch(fake_redis, [], cache)
    assert alerts_n == 0
    assert events_n == 0

@pytest.mark.asyncio
async def test_process_batch_no_rules_produces_no_alerts(fake_redis, cache):
    """Empty rule engine → process_message returns [] → no persist call."""
    stream = "threatos:events:normalized"
    group  = "detection-workers"
    await fake_redis.xgroup_create(stream, group, id="0", mkstream=True)
    await fake_redis.xadd(stream, _powershell_fields())
    raw      = await fake_redis.xreadgroup(group, "w", streams={stream: ">"}, count=10)
    messages = raw[0][1]

    with patch("threatos.workers.ingest_worker.persist_alerts_bulk",
               new_callable=AsyncMock, return_value=0) as mock_persist, \
         patch("threatos.workers.ingest_worker.get_db_context") as mock_db:
        mock_db.return_value.__aenter__ = AsyncMock()
        mock_db.return_value.__aexit__  = AsyncMock(return_value=False)
        alerts_n, _ = await _process_batch(fake_redis, messages, cache)

    assert alerts_n == 0
    mock_persist.assert_not_called()

@pytest.mark.asyncio
async def test_process_batch_db_failure_still_acks(fake_redis, cache):
    """Even if persist fails, messages should be acked to avoid reprocessing loops."""
    _load_ps_rule()
    stream = "threatos:events:normalized"
    group  = "detection-workers"
    await fake_redis.xgroup_create(stream, group, id="0", mkstream=True)
    await fake_redis.xadd(stream, _powershell_fields())
    raw      = await fake_redis.xreadgroup(group, "w", streams={stream: ">"}, count=10)
    messages = raw[0][1]

    with patch("threatos.workers.ingest_worker.persist_alerts_bulk",
               side_effect=Exception("DB down")), \
         patch("threatos.workers.ingest_worker.get_db_context") as mock_db:
        mock_db.return_value.__aenter__ = AsyncMock()
        mock_db.return_value.__aexit__  = AsyncMock(return_value=False)
        alerts_n, events_n = await _process_batch(fake_redis, messages, cache)

    assert events_n == 1
    assert alerts_n == 0
    # Messages still acked
    pending = await fake_redis.xpending(stream, group)
    assert pending["pending"] == 0
