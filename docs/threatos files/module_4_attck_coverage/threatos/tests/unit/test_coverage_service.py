"""
tests/unit/test_coverage_service.py
─────────────────────────────────────
Unit tests for coverage_service.py.
Uses SQLite in-memory DB (db_session fixture) and
injects ATT&CK cache via override_attck_cache — no network.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from threatos.core.attck_kb import ATTCKTechnique, override_attck_cache
from threatos.models.detection_rule import DetectionRule
from threatos.models.alert import Alert
from threatos.services.coverage_service import (
    CoverageSummary,
    get_coverage,
    get_coverage_summary,
    refresh_coverage,
)


# ── Shared test data ───────────────────────────────────────────────────────────

def _tech(tid: str, tactic: str = "execution") -> ATTCKTechnique:
    return ATTCKTechnique(
        id=tid, name=f"Technique {tid}", tactic=tactic,
        tactic_id="TA0002", platforms=["windows"],
        description="test", is_subtechnique=False, parent_id=None,
    )


SAMPLE_KB: dict[str, ATTCKTechnique] = {
    "T1059.001": _tech("T1059.001", "execution"),
    "T1003.001": _tech("T1003.001", "credential-access"),
    "T1110":     _tech("T1110",     "credential-access"),
}


def _rule(technique_id: str, confidence: float = 0.8) -> DetectionRule:
    return DetectionRule(
        id=uuid.uuid4(),
        name=f"Rule for {technique_id}",
        technique_id=technique_id,
        tactic="execution",
        log_sources=[],
        platforms=[],
        detection_ast={"type": "field_match", "field": "process",
                       "operator": "exists"},
        severity=5,
        confidence=confidence,
        tags=[],
        enabled=True,
        trigger_count=0,
    )


def _alert(technique_id: str) -> Alert:
    now = datetime.now(UTC)
    return Alert(
        id=uuid.uuid4(),
        technique_id=technique_id,
        tactic="execution",
        severity=7, confidence=0.8,
        asset_criticality=2, risk_score=50.0,
        status="open",
        created_at=now, updated_at=now,
    )


@pytest.fixture(autouse=True)
def inject_kb():
    override_attck_cache(SAMPLE_KB.copy())
    yield
    override_attck_cache({})


# ── refresh_coverage ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_refresh_populates_matrix_for_all_techniques(db_session):
    summary = await refresh_coverage(db_session)
    rows = await get_coverage(db_session)
    assert len(rows) == len(SAMPLE_KB)

@pytest.mark.asyncio
async def test_refresh_returns_correct_summary_all_gaps(db_session):
    summary = await refresh_coverage(db_session)
    # No rules seeded → all gaps
    assert summary.total_techniques == len(SAMPLE_KB)
    assert summary.covered   == 0
    assert summary.gaps      == len(SAMPLE_KB)
    assert summary.coverage_pct == 0.0

@pytest.mark.asyncio
async def test_refresh_marks_covered_when_rule_exists(db_session):
    db_session.add(_rule("T1059.001", confidence=0.9))
    await db_session.flush()

    await refresh_coverage(db_session)
    rows = await get_coverage(db_session)

    covered = {r.technique_id for r in rows if r.covered}
    gaps    = {r.technique_id for r in rows if not r.covered}

    assert "T1059.001" in covered
    assert "T1003.001" in gaps
    assert "T1110"     in gaps

@pytest.mark.asyncio
async def test_refresh_summary_counts_correctly_with_one_rule(db_session):
    db_session.add(_rule("T1059.001"))
    await db_session.flush()

    summary = await refresh_coverage(db_session)
    assert summary.covered == 1
    assert summary.gaps    == 2
    assert summary.coverage_pct == pytest.approx(33.3, abs=0.2)

@pytest.mark.asyncio
async def test_refresh_stores_confidence_avg(db_session):
    db_session.add(_rule("T1059.001", confidence=0.9))
    await db_session.flush()

    await refresh_coverage(db_session)
    rows = await get_coverage(db_session)
    row  = next(r for r in rows if r.technique_id == "T1059.001")
    assert abs(row.confidence_avg - 0.9) < 0.01

@pytest.mark.asyncio
async def test_refresh_multiple_rules_averages_confidence(db_session):
    # Add two rules with UNIQUE names covering the same technique
    r1 = _rule("T1059.001", confidence=0.6)
    r1.name = "Rule PS enc 1"
    r2 = _rule("T1059.001", confidence=0.8)
    r2.name = "Rule PS enc 2"
    db_session.add(r1)
    db_session.add(r2)
    await db_session.flush()

    await refresh_coverage(db_session)
    rows = await get_coverage(db_session)
    row  = next(r for r in rows if r.technique_id == "T1059.001")
    assert row.rule_count == 2
    # avg confidence of 0.6 and 0.8 = 0.7
    assert abs(row.confidence_avg - 0.7) < 0.01

@pytest.mark.asyncio
async def test_refresh_records_last_triggered_from_alerts(db_session):
    db_session.add(_rule("T1059.001"))
    db_session.add(_alert("T1059.001"))
    await db_session.flush()

    await refresh_coverage(db_session)
    rows = await get_coverage(db_session)
    row  = next(r for r in rows if r.technique_id == "T1059.001")
    assert row.last_triggered is not None

@pytest.mark.asyncio
async def test_refresh_no_last_triggered_when_no_alerts(db_session):
    db_session.add(_rule("T1059.001"))
    await db_session.flush()

    await refresh_coverage(db_session)
    rows = await get_coverage(db_session)
    row  = next(r for r in rows if r.technique_id == "T1059.001")
    assert row.last_triggered is None

@pytest.mark.asyncio
async def test_refresh_is_idempotent(db_session):
    db_session.add(_rule("T1059.001"))
    await db_session.flush()

    await refresh_coverage(db_session)
    await refresh_coverage(db_session)  # second call — should upsert cleanly
    rows = await get_coverage(db_session)
    assert len(rows) == len(SAMPLE_KB)

@pytest.mark.asyncio
async def test_refresh_empty_kb_returns_zero_summary(db_session):
    override_attck_cache({})
    summary = await refresh_coverage(db_session)
    assert summary.total_techniques == 0
    assert summary.coverage_pct == 0.0


# ── get_coverage ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_coverage_empty_before_refresh(db_session):
    rows = await get_coverage(db_session)
    assert rows == []

@pytest.mark.asyncio
async def test_get_coverage_returns_all_after_refresh(db_session):
    await refresh_coverage(db_session)
    rows = await get_coverage(db_session)
    assert len(rows) == len(SAMPLE_KB)

@pytest.mark.asyncio
async def test_get_coverage_filter_by_tactic(db_session):
    await refresh_coverage(db_session)
    rows = await get_coverage(db_session, tactic="credential-access")
    assert len(rows) == 2
    assert all(r.tactic == "credential-access" for r in rows)

@pytest.mark.asyncio
async def test_get_coverage_filter_covered_only(db_session):
    db_session.add(_rule("T1059.001"))
    await db_session.flush()
    await refresh_coverage(db_session)

    rows = await get_coverage(db_session, covered_only=True)
    assert len(rows) == 1
    assert rows[0].technique_id == "T1059.001"

@pytest.mark.asyncio
async def test_get_coverage_rows_have_correct_shape(db_session):
    await refresh_coverage(db_session)
    rows = await get_coverage(db_session)
    for row in rows:
        assert isinstance(row.technique_id,   str)
        assert isinstance(row.rule_count,     int)
        assert isinstance(row.confidence_avg, float)
        assert isinstance(row.covered,        bool)
        assert isinstance(row.platforms,      list)
        assert isinstance(row.priority_gap,   bool)


# ── get_coverage_summary ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_summary_zeros_before_refresh(db_session):
    summary = await get_coverage_summary(db_session)
    assert summary.total_techniques == 0
    assert summary.covered          == 0

@pytest.mark.asyncio
async def test_summary_after_refresh_no_rules(db_session):
    await refresh_coverage(db_session)
    summary = await get_coverage_summary(db_session)
    assert summary.total_techniques == len(SAMPLE_KB)
    assert summary.covered          == 0

@pytest.mark.asyncio
async def test_summary_after_refresh_with_rule(db_session):
    db_session.add(_rule("T1059.001"))
    await db_session.flush()
    await refresh_coverage(db_session)

    summary = await get_coverage_summary(db_session)
    assert summary.covered == 1
    assert summary.gaps    == len(SAMPLE_KB) - 1
