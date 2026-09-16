"""
tests/unit/test_chain_service.py
──────────────────────────────────
Unit tests for services/chain_service.py.
Uses SQLite in-memory via db_session fixture — no network.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from threatos.models.alert import Alert
from threatos.services.chain_service import (
    ChainFilters,
    ChainResult,
    _compute_chain_hash,
    _sort_tactics,
    correlate_alerts,
    get_chain_by_id,
    list_chains,
    update_chain_status,
)


# ── Test data helpers ─────────────────────────────────────────────────────────

def _alert(
    host:         str = "WIN-VICTIM",
    technique_id: str = "T1059.001",
    tactic:       str = "execution",
    risk_score:   float = 52.5,
    created_at:   datetime | None = None,
) -> Alert:
    now = created_at or datetime.now(UTC)
    return Alert(
        id=str(uuid.uuid4()),
        technique_id=technique_id,
        tactic=tactic,
        entity_host=host,
        severity=7, confidence=0.85,
        asset_criticality=2, risk_score=risk_score,
        status="open",
        created_at=now, updated_at=now,
    )


# ── _compute_chain_hash ───────────────────────────────────────────────────────

def test_chain_hash_is_deterministic():
    h1 = _compute_chain_hash("host", ["T1059.001", "T1003"])
    h2 = _compute_chain_hash("host", ["T1059.001", "T1003"])
    assert h1 == h2

def test_chain_hash_order_independent():
    h1 = _compute_chain_hash("host", ["T1059.001", "T1003"])
    h2 = _compute_chain_hash("host", ["T1003", "T1059.001"])
    assert h1 == h2

def test_chain_hash_differs_for_different_hosts():
    h1 = _compute_chain_hash("host-a", ["T1059.001"])
    h2 = _compute_chain_hash("host-b", ["T1059.001"])
    assert h1 != h2

def test_chain_hash_differs_for_different_techniques():
    h1 = _compute_chain_hash("host", ["T1059.001"])
    h2 = _compute_chain_hash("host", ["T1003.001"])
    assert h1 != h2

def test_chain_hash_is_64_chars():
    h = _compute_chain_hash("host", ["T1059.001"])
    assert len(h) == 64


# ── _sort_tactics ─────────────────────────────────────────────────────────────

def test_sort_tactics_kill_chain_order():
    tactics = ["impact", "execution", "initial-access"]
    sorted_t = _sort_tactics(tactics)
    assert sorted_t.index("initial-access") < sorted_t.index("execution")
    assert sorted_t.index("execution")     < sorted_t.index("impact")

def test_sort_tactics_deduplicates():
    tactics = ["execution", "execution", "persistence"]
    assert len(_sort_tactics(tactics)) == 2

def test_sort_tactics_unknown_goes_last():
    tactics = ["impact", "unknown-tactic"]
    sorted_t = _sort_tactics(tactics)
    assert sorted_t[-1] == "unknown-tactic"


# ── correlate_alerts ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_correlate_returns_none_when_no_alerts(db_session):
    result = await correlate_alerts(db_session, "WIN-VICTIM")
    assert result is None

@pytest.mark.asyncio
async def test_correlate_single_alert_creates_chain(db_session):
    db_session.add(_alert(host="WIN-VICTIM"))
    await db_session.flush()

    result = await correlate_alerts(db_session, "WIN-VICTIM")
    assert result is not None
    assert isinstance(result, ChainResult)
    assert result.created is True

@pytest.mark.asyncio
async def test_correlate_chain_persisted_to_db(db_session):
    db_session.add(_alert(host="WIN-VICTIM"))
    await db_session.flush()

    await correlate_alerts(db_session, "WIN-VICTIM")
    count = (await db_session.execute(
        text("SELECT COUNT(*) FROM attack_chains")
    )).scalar()
    assert count == 1

@pytest.mark.asyncio
async def test_correlate_correct_alert_count(db_session):
    for t in ("T1059.001", "T1003.001", "T1110"):
        db_session.add(_alert(host="WIN-VICTIM", technique_id=t))
    await db_session.flush()

    result = await correlate_alerts(db_session, "WIN-VICTIM")
    assert result.alert_count == 3

@pytest.mark.asyncio
async def test_correlate_risk_score_is_max_of_members(db_session):
    db_session.add(_alert(host="HOST", risk_score=30.0))
    db_session.add(_alert(host="HOST", risk_score=90.0))
    db_session.add(_alert(host="HOST", risk_score=55.0))
    await db_session.flush()

    result = await correlate_alerts(db_session, "HOST")
    assert result.risk_score == 90.0

@pytest.mark.asyncio
async def test_correlate_multi_stage_true_at_3_tactics(db_session):
    for tactic, tid in [
        ("initial-access",  "T1566"),
        ("execution",       "T1059.001"),
        ("privilege-escalation", "T1548"),
    ]:
        db_session.add(_alert(host="HOST", technique_id=tid, tactic=tactic))
    await db_session.flush()

    result = await correlate_alerts(db_session, "HOST")
    assert result.is_multi_stage is True
    assert result.tactic_count   == 3

@pytest.mark.asyncio
async def test_correlate_multi_stage_false_with_2_tactics(db_session):
    db_session.add(_alert(host="HOST", technique_id="T1059.001", tactic="execution"))
    db_session.add(_alert(host="HOST", technique_id="T1003.001", tactic="credential-access"))
    await db_session.flush()

    result = await correlate_alerts(db_session, "HOST")
    assert result.is_multi_stage is False

@pytest.mark.asyncio
async def test_correlate_is_idempotent(db_session):
    """Running correlation twice on the same alerts produces one chain row."""
    db_session.add(_alert(host="HOST"))
    await db_session.flush()

    r1 = await correlate_alerts(db_session, "HOST")
    await db_session.commit()
    r2 = await correlate_alerts(db_session, "HOST")

    assert r1.chain_id == r2.chain_id
    assert r2.created is False

    count = (await db_session.execute(
        text("SELECT COUNT(*) FROM attack_chains")
    )).scalar()
    assert count == 1

@pytest.mark.asyncio
async def test_correlate_respects_window_excludes_old_alerts(db_session):
    """Alert older than the window must not be included."""
    old_time = datetime.now(UTC) - timedelta(hours=48)
    db_session.add(_alert(host="HOST", created_at=old_time))
    # No alerts within the default 24h window
    await db_session.flush()

    result = await correlate_alerts(db_session, "HOST", window_hours=24)
    assert result is None

@pytest.mark.asyncio
async def test_correlate_only_includes_open_alerts(db_session):
    """Closed alerts must not be included in correlation."""
    now   = datetime.now(UTC)
    open_a = _alert(host="HOST")
    open_a.status = "open"

    closed_a = Alert(
        id=str(uuid.uuid4()), technique_id="T1110",
        tactic="credential-access", entity_host="HOST",
        severity=5, confidence=0.7, asset_criticality=2, risk_score=30.0,
        status="closed",
        created_at=now, updated_at=now,
    )
    db_session.add(open_a)
    db_session.add(closed_a)
    await db_session.flush()

    result = await correlate_alerts(db_session, "HOST")
    # Only the open alert should be included
    assert result.alert_count == 1

@pytest.mark.asyncio
async def test_correlate_different_hosts_produce_different_chains(db_session):
    db_session.add(_alert(host="WIN-A"))
    db_session.add(_alert(host="WIN-B"))
    await db_session.flush()

    r_a = await correlate_alerts(db_session, "WIN-A")
    r_b = await correlate_alerts(db_session, "WIN-B")
    assert r_a.chain_id != r_b.chain_id


# ── get_chain_by_id ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_chain_by_id_returns_chain(db_session):
    db_session.add(_alert(host="HOST"))
    await db_session.flush()

    result  = await correlate_alerts(db_session, "HOST")
    chain   = await get_chain_by_id(db_session, result.chain_id)
    assert chain is not None
    assert str(chain.id) == result.chain_id

@pytest.mark.asyncio
async def test_get_chain_by_id_returns_none_for_missing(db_session):
    chain = await get_chain_by_id(db_session, str(uuid.uuid4()))
    assert chain is None


# ── list_chains ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_chains_returns_all(db_session):
    for host in ("WIN-A", "WIN-B", "WIN-C"):
        db_session.add(_alert(host=host))
    await db_session.flush()

    for host in ("WIN-A", "WIN-B", "WIN-C"):
        await correlate_alerts(db_session, host)
    await db_session.commit()

    chains = await list_chains(db_session)
    assert len(chains) == 3

@pytest.mark.asyncio
async def test_list_chains_ordered_by_risk_score_desc(db_session):
    for host, score in [("H1", 20.0), ("H2", 90.0), ("H3", 55.0)]:
        db_session.add(_alert(host=host, risk_score=score))
    await db_session.flush()
    for host in ("H1", "H2", "H3"):
        await correlate_alerts(db_session, host)
    await db_session.commit()

    chains = await list_chains(db_session)
    scores = [c.risk_score for c in chains]
    assert scores == sorted(scores, reverse=True)

@pytest.mark.asyncio
async def test_list_chains_filter_by_host(db_session):
    db_session.add(_alert(host="WIN-A"))
    db_session.add(_alert(host="WIN-B"))
    await db_session.flush()
    await correlate_alerts(db_session, "WIN-A")
    await correlate_alerts(db_session, "WIN-B")
    await db_session.commit()

    chains = await list_chains(db_session, ChainFilters(host="WIN-A"))
    assert len(chains) == 1
    assert chains[0].host == "win-a"

@pytest.mark.asyncio
async def test_list_chains_filter_multi_stage(db_session):
    # Build a multi-stage chain (3 tactics)
    for tactic, tid in [
        ("initial-access","T1566"),("execution","T1059.001"),("persistence","T1547")
    ]:
        db_session.add(_alert(host="MULTI", technique_id=tid, tactic=tactic))
    # Build a single-stage chain
    db_session.add(_alert(host="SINGLE"))
    await db_session.flush()
    await correlate_alerts(db_session, "MULTI")
    await correlate_alerts(db_session, "SINGLE")
    await db_session.commit()

    chains = await list_chains(db_session, ChainFilters(is_multi_stage=True))
    assert len(chains) == 1
    assert chains[0].host == "multi"

@pytest.mark.asyncio
async def test_list_chains_empty_before_correlation(db_session):
    chains = await list_chains(db_session)
    assert chains == []


# ── update_chain_status ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_chain_status_changes_status(db_session):
    db_session.add(_alert(host="HOST"))
    await db_session.flush()
    result = await correlate_alerts(db_session, "HOST")
    await db_session.commit()

    updated = await update_chain_status(db_session, result.chain_id, "investigating")
    assert updated is not None
    assert updated.status == "investigating"

@pytest.mark.asyncio
async def test_update_chain_status_invalid_raises(db_session):
    db_session.add(_alert(host="HOST"))
    await db_session.flush()
    result = await correlate_alerts(db_session, "HOST")

    with pytest.raises(ValueError, match="Invalid chain status"):
        await update_chain_status(db_session, result.chain_id, "NONSENSE")

@pytest.mark.asyncio
async def test_update_chain_status_missing_returns_none(db_session):
    updated = await update_chain_status(db_session, str(uuid.uuid4()), "closed")
    assert updated is None
