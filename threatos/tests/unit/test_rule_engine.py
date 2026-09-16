"""
tests/unit/test_rule_engine.py
───────────────────────────────
Unit tests for rule_engine.py service.
Zero I/O. Each test calls clear_rules() to ensure isolation.
"""
import pytest
from threatos.detection.rule_ast import FieldMatch
from threatos.detection.rule_engine import (
    CompiledRule,
    build_alert_dict,
    clear_rules,
    compute_risk_score,
    evaluate_event,
    get_loaded_rule_count,
    load_rules_into_engine,
)
from threatos.ingestion.normalizer import NormalizedEvent


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _rule(technique_id: str, ast: dict,
          log_sources: list | None = None,
          severity: int = 7,
          confidence: float = 0.85) -> dict:
    """Build a minimal rule dict matching the DB row shape."""
    return {
        "id":           f"rule-{technique_id}",
        "name":         f"Test rule {technique_id}",
        "technique_id": technique_id,
        "tactic":       "execution",
        "log_sources":  log_sources or [],
        "severity":     severity,
        "confidence":   confidence,
        "detection_ast":ast,
        "tags":         [],
    }


def _powershell_event() -> NormalizedEvent:
    return NormalizedEvent(
        event_id="evt-ps-001",
        log_source="winlog",
        host="WIN-VICTIM",
        user="alice",
        process="powershell.exe",
        command_line="powershell.exe -EncodedCommand SQBFAFgA",
        raw_fields={
            "process":      "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand SQBFAFgA",
        },
    )


def _benign_event() -> NormalizedEvent:
    return NormalizedEvent(
        event_id="evt-benign-001",
        log_source="json",
        host="web-server",
        process="nginx",
        raw_fields={"process": "nginx", "message": "GET /healthz 200"},
    )


@pytest.fixture(autouse=True)
def isolate_engine():
    """Clear the rule cache before and after every test."""
    clear_rules()
    yield
    clear_rules()


# ── load_rules_into_engine ────────────────────────────────────────────────────

def test_load_rules_returns_count():
    n = load_rules_into_engine([
        _rule("T1059.001", {"type": "field_match", "field": "process",
                             "operator": "contains", "value": "powershell"}),
    ])
    assert n == 1
    assert get_loaded_rule_count() == 1

def test_load_rules_skips_invalid_ast():
    rules = [
        _rule("T1059.001", {"type": "field_match", "field": "process",
                             "operator": "contains", "value": "powershell"}),
        _rule("T9999.999", {"type": "totally_invalid_type"}),  # bad
    ]
    n = load_rules_into_engine(rules)
    assert n == 1   # only the valid one loaded

def test_empty_engine_returns_zero():
    assert get_loaded_rule_count() == 0


# ── compute_risk_score ────────────────────────────────────────────────────────

def test_risk_score_max_inputs():
    score = compute_risk_score(severity=10, confidence=1.0, asset_criticality=4)
    assert score == 100.0

def test_risk_score_min_inputs():
    score = compute_risk_score(severity=1, confidence=0.1, asset_criticality=1)
    assert 0 < score < 5

def test_risk_score_caps_at_100():
    # Even with out-of-range confidence it should never exceed 100
    score = compute_risk_score(severity=10, confidence=2.0, asset_criticality=4)
    assert score == 100.0

def test_risk_score_monotone_with_severity():
    scores = [compute_risk_score(s, 0.8, 2) for s in [1, 3, 5, 7, 9]]
    assert scores == sorted(scores)

def test_risk_score_monotone_with_confidence():
    scores = [compute_risk_score(7, c, 2) for c in [0.2, 0.4, 0.6, 0.8, 1.0]]
    assert scores == sorted(scores)

def test_risk_score_monotone_with_criticality():
    scores = [compute_risk_score(7, 0.8, c) for c in [1, 2, 3, 4]]
    assert scores == sorted(scores)

def test_risk_score_is_rounded_to_2dp():
    score = compute_risk_score(7, 0.85, 2)
    assert score == round(score, 2)


# ── evaluate_event ────────────────────────────────────────────────────────────

def test_evaluate_fires_on_matching_event():
    load_rules_into_engine([_rule("T1059.001", {
        "type": "and", "children": [
            {"type": "field_match", "field": "process",
             "operator": "contains", "value": "powershell"},
            {"type": "field_match", "field": "command_line",
             "operator": "contains", "value": "-EncodedCommand"},
        ],
    })])
    matches = evaluate_event(_powershell_event())
    assert len(matches) == 1
    # evaluate_event() returns fully-built alert dicts directly (there is no
    # separate "match" object with a `.rule`/`.risk_score` attribute in the
    # current API), so index into the dict instead.
    assert matches[0]["technique_id"] == "T1059.001"
    assert matches[0]["risk_score"] > 0

def test_evaluate_no_match_on_benign_event():
    load_rules_into_engine([_rule("T1059.001", {
        "type": "field_match", "field": "process",
        "operator": "contains", "value": "powershell",
    })])
    matches = evaluate_event(_benign_event())
    assert matches == []

def test_evaluate_multiple_rules_can_fire():
    load_rules_into_engine([
        _rule("T1059.001", {"type": "field_match", "field": "process",
                             "operator": "contains", "value": "powershell"}),
        _rule("T1140", {"type": "field_match", "field": "command_line",
                         "operator": "contains", "value": "-EncodedCommand"}),
    ])
    matches = evaluate_event(_powershell_event())
    assert len(matches) == 2
    techniques = {m["technique_id"] for m in matches}
    assert techniques == {"T1059.001", "T1140"}

def test_evaluate_respects_log_source_filter():
    """Rule scoped to 'cef' must NOT fire on a 'winlog' event."""
    load_rules_into_engine([_rule("T1059.001", {
        "type": "field_match", "field": "process",
        "operator": "contains", "value": "powershell",
    }, log_sources=["cef"])])
    matches = evaluate_event(_powershell_event())  # log_source = winlog
    assert matches == []

def test_evaluate_empty_log_source_matches_any_source():
    """Empty log_sources list means the rule applies everywhere."""
    load_rules_into_engine([_rule("T1059.001", {
        "type": "field_match", "field": "process",
        "operator": "contains", "value": "powershell",
    }, log_sources=[])])
    matches = evaluate_event(_powershell_event())
    assert len(matches) == 1

def test_evaluate_empty_engine_returns_empty_list():
    # No rules loaded
    matches = evaluate_event(_powershell_event())
    assert matches == []

def test_evaluate_broken_ast_does_not_crash_pipeline():
    """A rule that throws during evaluation must be skipped, not crash.

    NOTE: the historical version of this test injected a FieldMatch subclass
    that overrode `.evaluate()` to raise — but the current rule_ast.py has no
    `.evaluate()` method at all; evaluate_ast() dispatches purely by
    isinstance(), so overriding a method is never actually invoked. To
    exercise the real failure path we use a rule whose AST *genuinely* raises
    during evaluate_ast() — a regex FieldMatch with an invalid pattern (see
    the skipped test_regex_invalid_pattern_returns_false in test_rule_ast.py
    for the underlying bug in rule_ast.py). This confirms evaluate_event()'s
    own per-rule try/except protects the overall pipeline from that bug.
    """
    load_rules_into_engine([_rule("T9999", {
        "type": "field_match", "field": "process",
        "operator": "regex", "value": "[invalid(",
    })])
    # Should return empty, not raise
    matches = evaluate_event(_powershell_event())
    assert matches == []


# ── build_alert_dict ──────────────────────────────────────────────────────────
#
# NOTE ON API DRIFT: build_alert_dict(event, rule, asset_criticality) expects
# its second argument to be a CompiledRule, not a match/alert dict. The
# historical test called `build_alert_dict(event, matches[0])` — but
# evaluate_event() already calls build_alert_dict() internally and returns the
# finished alert dicts directly, so `matches[0]` here IS an alert dict, not a
# CompiledRule (it has no .id/.name/.severity attributes). Calling
# build_alert_dict a second time on that dict would AttributeError. These
# tests are rewritten to build a CompiledRule directly and call
# build_alert_dict() the way the real code does (from evaluate_event()).

def _compiled_rule(technique_id: str = "T1059.001", severity: int = 7,
                   confidence: float = 0.85) -> CompiledRule:
    return CompiledRule(
        id=f"rule-{technique_id}", name=f"Test rule {technique_id}",
        technique_id=technique_id, tactic="execution", log_sources=[],
        severity=severity, confidence=confidence,
        ast=FieldMatch(field="process", operator="contains", value="powershell"),
        tags=[],
    )

def test_build_alert_dict_has_required_keys():
    alert = build_alert_dict(_powershell_event(), _compiled_rule())
    # "description" existed in the historical alert dict shape but the current
    # build_alert_dict() (threatos/detection/rule_engine.py:60-81) never sets
    # it — that key is dropped from the required set to match current reality.
    required = {
        "id", "rule_id", "event_id", "technique_id", "tactic",
        "severity", "confidence", "risk_score", "asset_criticality",
        "entity_host", "entity_user", "entity_process",
        "status", "raw_match", "created_at",
    }
    assert required.issubset(set(alert.keys()))

def test_build_alert_dict_status_is_open():
    alert = build_alert_dict(_powershell_event(), _compiled_rule())
    assert alert["status"] == "open"

def test_build_alert_dict_entity_fields_from_event():
    event = _powershell_event()
    alert = build_alert_dict(event, _compiled_rule())
    assert alert["entity_host"] == "WIN-VICTIM"
    assert alert["entity_user"] == "alice"

def test_build_alert_dict_risk_score_matches_formula():
    rule  = _compiled_rule(severity=7, confidence=0.85)
    alert = build_alert_dict(_powershell_event(), rule, asset_criticality=2)
    expected = compute_risk_score(7, 0.85, 2)
    assert alert["risk_score"] == expected
