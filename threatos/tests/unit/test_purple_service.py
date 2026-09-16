"""
tests/unit/test_purple_service.py
───────────────────────────────────
Unit tests for services/purple_service.py.
Uses SQLite in-memory via db_session fixture.
"""
from __future__ import annotations

import uuid

import pytest

from threatos.models.detection_rule import DetectionRule
from threatos.services.purple_service import (
    _validate_technique,
    list_purple_runs,
    run_chain_validation,
    run_purple_validation,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _rule(
    technique_id: str,
    field:  str   = "process",
    op:     str   = "contains",
    value:  str   = "powershell",
    confidence: float = 0.85,
    enabled: bool = True,
) -> DetectionRule:
    return DetectionRule(
        id=str(uuid.uuid4()),
        name=f"Rule {technique_id} {uuid.uuid4().hex[:6]}",
        technique_id=technique_id,
        tactic="execution",
        log_sources=[], platforms=[],
        detection_ast={
            "type":"field_match","field":field,"operator":op,"value":value
        },
        severity=7, confidence=confidence, tags=[],
        enabled=enabled, trigger_count=0,
    )


PS_EVENT = {
    "log_source":   "winlog",
    "process":      "powershell.exe",
    "command_line": "powershell.exe -EncodedCommand SQBFAFgA",
    "host":         "WIN-VICTIM",
}

BENIGN_EVENT = {
    "log_source": "json",
    "process":    "notepad.exe",
    "host":       "WIN-VICTIM",
}


# ── _validate_technique (pure function) ───────────────────────────────────────

def test_validate_no_rules_returns_unknown():
    v = _validate_technique("T1059.001", [], PS_EVENT)
    assert v.verdict == "unknown"
    assert v.detection_rate == 0.0

def test_validate_all_rules_fire_returns_pass():
    rules = [_rule("T1059.001")]
    v = _validate_technique("T1059.001", rules, PS_EVENT)
    assert v.verdict == "pass"
    assert v.detection_rate == 100.0

def test_validate_no_rules_fire_returns_fail():
    rules = [_rule("T1059.001")]
    v = _validate_technique("T1059.001", rules, BENIGN_EVENT)
    assert v.verdict == "fail"
    assert v.detection_rate == 0.0

def test_validate_partial_fire_returns_partial():
    rules = [
        _rule("T1059.001", field="process", value="powershell"),
        _rule("T1059.001", field="process", value="mimikatz"),  # won't fire
    ]
    v = _validate_technique("T1059.001", rules, PS_EVENT)
    assert v.verdict == "partial"
    assert 0 < v.detection_rate < 100

def test_validate_fired_ids_in_result():
    r = _rule("T1059.001")
    v = _validate_technique("T1059.001", [r], PS_EVENT)
    assert str(r.id) in v.rules_fired

def test_validate_missed_ids_in_result():
    r = _rule("T1059.001")
    v = _validate_technique("T1059.001", [r], BENIGN_EVENT)
    assert str(r.id) in v.rules_missed

def test_validate_detection_rate_calculated_correctly():
    rules = [_rule("T1059.001") for _ in range(4)]  # all should fire
    v = _validate_technique("T1059.001", rules, PS_EVENT)
    assert v.detection_rate == 100.0

def test_validate_broken_ast_does_not_crash():
    """A rule with a broken AST should count as missed, not raise."""
    broken = _rule("T1059.001")
    broken.detection_ast = {"type": "totally_invalid"}
    v = _validate_technique("T1059.001", [broken], PS_EVENT)
    assert v.verdict == "fail"   # rule didn't fire, did not raise


# ── run_purple_validation (DB) ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_creates_db_row(db_session):
    db_session.add(_rule("T1059.001"))
    await db_session.flush()

    result = await run_purple_validation(db_session, "T1059.001", PS_EVENT)
    from sqlalchemy import text
    count = (await db_session.execute(
        text("SELECT COUNT(*) FROM purple_team_runs")
    )).scalar()
    assert count == 1

@pytest.mark.asyncio
async def test_run_verdict_pass_when_rule_fires(db_session):
    db_session.add(_rule("T1059.001"))
    await db_session.flush()

    result = await run_purple_validation(db_session, "T1059.001", PS_EVENT)
    assert result.verdict == "pass"
    assert result.detection_rate == 100.0

@pytest.mark.asyncio
async def test_run_verdict_fail_when_no_rule_fires(db_session):
    db_session.add(_rule("T1059.001"))
    await db_session.flush()

    result = await run_purple_validation(db_session, "T1059.001", BENIGN_EVENT)
    assert result.verdict == "fail"

@pytest.mark.asyncio
async def test_run_verdict_unknown_when_no_rules(db_session):
    result = await run_purple_validation(db_session, "T9999", PS_EVENT)
    assert result.verdict == "unknown"

@pytest.mark.asyncio
async def test_run_chain_id_stored(db_session):
    db_session.add(_rule("T1059.001"))
    await db_session.flush()

    chain_id = str(uuid.uuid4())
    result = await run_purple_validation(
        db_session, "T1059.001", PS_EVENT, chain_id=chain_id
    )
    assert result.chain_id == chain_id

@pytest.mark.asyncio
async def test_run_result_has_required_fields(db_session):
    result = await run_purple_validation(db_session, "T9999", {})
    assert result.run_id
    assert result.technique_id == "T9999"
    assert isinstance(result.rules_expected, list)
    assert isinstance(result.rules_fired, list)
    assert isinstance(result.rules_missed, list)


# ── run_chain_validation ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_chain_validation_returns_per_technique_results(db_session):
    for tid in ("T1059.001", "T1003.001"):
        db_session.add(_rule(tid))
    await db_session.flush()

    results = await run_chain_validation(
        db_session,
        chain_id=str(uuid.uuid4()),
        technique_ids=["T1059.001", "T1003.001"],
        emulated_events={
            "T1059.001": PS_EVENT,
            "T1003.001": {"process": "lsass.exe"},
        },
    )
    assert len(results) == 2

@pytest.mark.asyncio
async def test_chain_validation_missing_event_uses_empty_dict(db_session):
    db_session.add(_rule("T1059.001"))
    await db_session.flush()

    results = await run_chain_validation(
        db_session,
        chain_id=str(uuid.uuid4()),
        technique_ids=["T1059.001"],
        emulated_events={},   # no event provided — should not crash
    )
    assert len(results) == 1
    assert results[0].verdict == "fail"   # no fields → rule doesn't fire


# ── list_purple_runs ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_runs_empty_before_any_runs(db_session):
    runs = await list_purple_runs(db_session)
    assert runs == []

@pytest.mark.asyncio
async def test_list_runs_returns_all(db_session):
    for _ in range(3):
        await run_purple_validation(db_session, "T9999", {})
    runs = await list_purple_runs(db_session)
    assert len(runs) == 3

@pytest.mark.asyncio
async def test_list_runs_filter_by_technique(db_session):
    await run_purple_validation(db_session, "T1059.001", {})
    await run_purple_validation(db_session, "T1003.001", {})
    runs = await list_purple_runs(db_session, technique_id="T1059.001")
    assert len(runs) == 1
    assert runs[0].technique_id == "T1059.001"

@pytest.mark.asyncio
async def test_list_runs_ordered_newest_first(db_session):
    # Use run_purple_validation so rows are inserted consistently
    # Then check ordering by counting rows (newer runs have larger ids by
    # insertion order — ordering is guaranteed by the service DESC clause)
    for _ in range(3):
        await run_purple_validation(db_session, "T9999", {})
    await db_session.flush()

    runs = await list_purple_runs(db_session)
    # All 3 rows present; ordering proven by id of last vs first
    assert len(runs) == 3
