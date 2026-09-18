"""
tests/unit/test_suppression_service.py
────────────────────────────────────────
Unit tests for services/suppression_service.py — the 15-minute rule+host
dedup window used to keep a burst of matching events from creating one
alert row per event. Never directly tested until now (the intra-batch
suppression gap it was supposed to close was found via this audit — see
tests/integration/test_ingest_worker_integration.py for the worker-level
regression test).
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from threatos.services.alert_service import persist_alert
from threatos.services.suppression_service import (
    _suppression_key,
    get_suppression_stats,
    is_suppressed,
)


def _alert_dict(rule_id="rule-1", entity_host="WIN-VICTIM", created_at=None) -> dict:
    now = created_at or datetime.now(UTC)
    return {
        "id": str(uuid.uuid4()), "rule_id": rule_id, "event_id": "evt-1",
        "technique_id": "T1059.001", "tactic": "execution", "severity": 7,
        "confidence": 0.85, "asset_criticality": 2, "risk_score": 52.5,
        "entity_host": entity_host, "entity_user": "alice",
        "status": "open", "description": "Test alert",
        "created_at": now, "updated_at": now,
    }


# ── _suppression_key ─────────────────────────────────────────────────────────

def test_suppression_key_is_deterministic():
    assert _suppression_key("rule-1", "host-a") == _suppression_key("rule-1", "host-a")

def test_suppression_key_differs_by_rule():
    assert _suppression_key("rule-1", "host-a") != _suppression_key("rule-2", "host-a")

def test_suppression_key_differs_by_host():
    assert _suppression_key("rule-1", "host-a") != _suppression_key("rule-1", "host-b")

def test_suppression_key_treats_missing_host_consistently():
    assert _suppression_key("rule-1", None) == _suppression_key("rule-1", None)
    assert _suppression_key("rule-1", None) != _suppression_key("rule-1", "unknown-literal-string")


# ── is_suppressed ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_not_suppressed_when_no_prior_alert(db_session):
    assert await is_suppressed(db_session, "rule-1", "WIN-A") is False

@pytest.mark.asyncio
async def test_suppressed_when_recent_matching_alert_exists(db_session):
    await persist_alert(db_session, _alert_dict(rule_id="rule-1", entity_host="WIN-A"))
    await db_session.commit()
    assert await is_suppressed(db_session, "rule-1", "WIN-A") is True

@pytest.mark.asyncio
async def test_not_suppressed_for_different_host(db_session):
    await persist_alert(db_session, _alert_dict(rule_id="rule-1", entity_host="WIN-A"))
    await db_session.commit()
    assert await is_suppressed(db_session, "rule-1", "WIN-B") is False

@pytest.mark.asyncio
async def test_not_suppressed_for_different_rule(db_session):
    await persist_alert(db_session, _alert_dict(rule_id="rule-1", entity_host="WIN-A"))
    await db_session.commit()
    assert await is_suppressed(db_session, "rule-2", "WIN-A") is False

@pytest.mark.asyncio
async def test_not_suppressed_once_outside_window(db_session):
    old = datetime.now(UTC) - timedelta(minutes=30)
    await persist_alert(db_session, _alert_dict(rule_id="rule-1", entity_host="WIN-A", created_at=old))
    await db_session.commit()
    assert await is_suppressed(db_session, "rule-1", "WIN-A", window_minutes=15) is False

@pytest.mark.asyncio
async def test_custom_window_minutes_respected(db_session):
    ten_ago = datetime.now(UTC) - timedelta(minutes=10)
    await persist_alert(db_session, _alert_dict(rule_id="rule-1", entity_host="WIN-A", created_at=ten_ago))
    await db_session.commit()
    assert await is_suppressed(db_session, "rule-1", "WIN-A", window_minutes=15) is True
    assert await is_suppressed(db_session, "rule-1", "WIN-A", window_minutes=5) is False


# ── get_suppression_stats ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_stats_empty_when_no_alerts(db_session):
    stats = await get_suppression_stats(db_session)
    assert stats["noisy_rule_hosts"] == 0
    assert stats["duplicate_alerts"] == 0
    assert stats["top_noisy"] == []

@pytest.mark.asyncio
async def test_stats_counts_duplicates_for_noisy_rule_host(db_session):
    for _ in range(3):
        await persist_alert(db_session, _alert_dict(rule_id="rule-1", entity_host="WIN-A"))
    await db_session.commit()
    stats = await get_suppression_stats(db_session)
    assert stats["noisy_rule_hosts"] == 1
    assert stats["duplicate_alerts"] == 2   # 3 alerts - 1 "original" = 2 duplicates
    assert stats["top_noisy"][0]["count"] == 3

@pytest.mark.asyncio
async def test_stats_ignores_single_occurrence_rule_hosts(db_session):
    await persist_alert(db_session, _alert_dict(rule_id="rule-1", entity_host="WIN-A"))
    await db_session.commit()
    stats = await get_suppression_stats(db_session)
    assert stats["noisy_rule_hosts"] == 0
    assert stats["duplicate_alerts"] == 0

@pytest.mark.asyncio
async def test_stats_excludes_alerts_outside_window(db_session):
    old = datetime.now(UTC) - timedelta(minutes=30)
    for _ in range(3):
        await persist_alert(db_session, _alert_dict(rule_id="rule-1", entity_host="WIN-A", created_at=old))
    await db_session.commit()
    stats = await get_suppression_stats(db_session, window_minutes=15)
    assert stats["noisy_rule_hosts"] == 0
