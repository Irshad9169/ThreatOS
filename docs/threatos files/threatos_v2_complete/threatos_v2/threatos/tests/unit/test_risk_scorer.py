"""
tests/unit/test_risk_scorer.py
────────────────────────────────
Unit tests for detection/risk_scorer.py.
Pure function tests — zero I/O.
"""
import pytest
from threatos.detection.risk_scorer import (
    ScoreComponents,
    compute_score_v1,
    compute_score_v2,
    rescore_alert_for_chain,
    score_alert_in_context,
)


# ── compute_score_v1 ──────────────────────────────────────────────────────────

def test_v1_max_inputs_gives_100():
    assert compute_score_v1(10, 1.0, 4) == 100.0

def test_v1_minimum_inputs_above_zero():
    score = compute_score_v1(1, 0.1, 1)
    assert 0 < score < 5

def test_v1_caps_at_100():
    assert compute_score_v1(10, 2.0, 4) == 100.0

def test_v1_monotone_severity():
    scores = [compute_score_v1(s, 0.8, 2) for s in range(1, 11)]
    assert scores == sorted(scores)

def test_v1_monotone_confidence():
    scores = [compute_score_v1(7, c/10, 2) for c in range(1, 11)]
    assert scores == sorted(scores)

def test_v1_matches_rule_engine_formula():
    """v1 must be identical to the formula in rule_engine.py."""
    from threatos.detection.rule_engine import compute_risk_score
    for s in (3, 5, 7, 9):
        for c in (0.5, 0.7, 0.9):
            for crit in (1, 2, 3, 4):
                assert compute_score_v1(s, c, crit) == compute_risk_score(s, c, crit)


# ── compute_score_v2 ──────────────────────────────────────────────────────────

def test_v2_returns_score_components():
    result = compute_score_v2(7, 0.85, 2, chain_tactic_count=1)
    assert isinstance(result, ScoreComponents)

def test_v2_standalone_equals_v1():
    """With tactic_count=1 and not multi-stage, v2 must equal v1."""
    v1 = compute_score_v1(7, 0.85, 2)
    v2 = compute_score_v2(7, 0.85, 2, chain_tactic_count=1, is_multi_stage=False)
    assert v2.final_score == v1

def test_v2_chain_boost_increases_score():
    standalone = compute_score_v2(7, 0.85, 2, chain_tactic_count=1)
    in_chain   = compute_score_v2(7, 0.85, 2, chain_tactic_count=4)
    assert in_chain.final_score > standalone.final_score

def test_v2_multi_stage_boost_increases_score():
    single_stage = compute_score_v2(7, 0.85, 2, chain_tactic_count=3, is_multi_stage=False)
    multi_stage  = compute_score_v2(7, 0.85, 2, chain_tactic_count=3, is_multi_stage=True)
    assert multi_stage.final_score > single_stage.final_score

def test_v2_multi_stage_boost_is_125_percent():
    a = compute_score_v2(7, 0.85, 2, chain_tactic_count=3, is_multi_stage=False)
    b = compute_score_v2(7, 0.85, 2, chain_tactic_count=3, is_multi_stage=True)
    assert abs(b.final_score - a.final_score * 1.25) < 0.1

def test_v2_tactic_step_is_15_percent_per_tactic():
    base   = compute_score_v2(7, 0.85, 2, chain_tactic_count=1).base_score
    two_t  = compute_score_v2(7, 0.85, 2, chain_tactic_count=2)
    assert abs(two_t.chain_boost - 1.15) < 0.001

def test_v2_chain_boost_caps_at_2x():
    very_long = compute_score_v2(7, 0.85, 2, chain_tactic_count=100)
    assert very_long.chain_boost == 2.0

def test_v2_final_score_never_exceeds_100():
    score = compute_score_v2(10, 1.0, 4, chain_tactic_count=14, is_multi_stage=True)
    assert score.final_score <= 100.0

def test_v2_all_components_in_result():
    result = compute_score_v2(7, 0.85, 2, chain_tactic_count=3, is_multi_stage=True)
    d = result.as_dict()
    required = {
        "severity","confidence","asset_criticality",
        "chain_tactic_count","is_multi_stage",
        "base_score","chain_boost","stage_boost","final_score",
    }
    assert required == set(d.keys())

def test_v2_severity_clamped_to_valid_range():
    # severity=0 should be clamped to 1
    r = compute_score_v2(0, 0.8, 2)
    assert r.severity == 1
    # severity=99 clamped to 10
    r = compute_score_v2(99, 0.8, 2)
    assert r.severity == 10

def test_v2_confidence_clamped():
    r = compute_score_v2(7, 1.5, 2)
    assert r.confidence == 1.0

def test_v2_criticality_clamped():
    r = compute_score_v2(7, 0.8, 0)
    assert r.asset_criticality == 1
    r = compute_score_v2(7, 0.8, 9)
    assert r.asset_criticality == 4


# ── score_alert_in_context ────────────────────────────────────────────────────

def test_score_in_context_returns_float():
    result = score_alert_in_context(7, 0.85, 2, 1, False)
    assert isinstance(result, float)

def test_score_in_context_matches_v2_final():
    v2 = compute_score_v2(7, 0.85, 2, 3, True)
    sc = score_alert_in_context(7, 0.85, 2, 3, True)
    assert sc == v2.final_score


# ── rescore_alert_for_chain ───────────────────────────────────────────────────

def test_rescore_standalone_no_change():
    base = compute_score_v1(7, 0.85, 2)
    rescored = rescore_alert_for_chain(base, chain_tactic_count=1, is_multi_stage=False)
    assert rescored == base

def test_rescore_increases_for_chain():
    base     = compute_score_v1(7, 0.85, 2)
    rescored = rescore_alert_for_chain(base, chain_tactic_count=3, is_multi_stage=False)
    assert rescored > base

def test_rescore_further_increases_for_multi_stage():
    base  = compute_score_v1(7, 0.85, 2)
    s3    = rescore_alert_for_chain(base, 3, is_multi_stage=False)
    s3ms  = rescore_alert_for_chain(base, 3, is_multi_stage=True)
    assert s3ms > s3

def test_rescore_never_exceeds_100():
    rescored = rescore_alert_for_chain(99.0, chain_tactic_count=14, is_multi_stage=True)
    assert rescored <= 100.0

def test_rescore_is_monotone_with_tactic_count():
    base   = 30.0
    scores = [rescore_alert_for_chain(base, tc, False) for tc in range(1, 10)]
    assert scores == sorted(scores)
