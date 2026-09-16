"""
tests/unit/test_attck_kb.py
────────────────────────────
Unit tests for core/attck_kb.py.
No network calls — all tests inject data via override_attck_cache().
"""
from __future__ import annotations

import pytest
from threatos.core.attck_kb import (
    ATTCKTechnique,
    TACTIC_ORDER,
    get_all_technique_ids,
    get_cache_size,
    get_tactic_order,
    get_technique,
    override_attck_cache,
    validate_technique_id,
)


# ── Shared fixtures ────────────────────────────────────────────────────────────

def _make_technique(
    tid: str = "T1059.001",
    name: str = "PowerShell",
    tactic: str = "execution",
    platforms: list[str] | None = None,
    is_sub: bool = True,
    parent: str | None = "T1059",
) -> ATTCKTechnique:
    return ATTCKTechnique(
        id=tid,
        name=name,
        tactic=tactic,
        tactic_id="TA0002",
        platforms=platforms or ["windows"],
        description="Test technique",
        is_subtechnique=is_sub,
        parent_id=parent,
    )


SAMPLE_CACHE: dict[str, ATTCKTechnique] = {
    "T1059":     _make_technique("T1059",     "Command and Scripting Interpreter",
                                 tactic="execution",         is_sub=False, parent=None),
    "T1059.001": _make_technique("T1059.001", "PowerShell",
                                 tactic="execution",         is_sub=True,  parent="T1059"),
    "T1003":     _make_technique("T1003",     "OS Credential Dumping",
                                 tactic="credential-access", is_sub=False, parent=None),
    "T1003.001": _make_technique("T1003.001", "LSASS Memory",
                                 tactic="credential-access", is_sub=True,  parent="T1003"),
    "T1110":     _make_technique("T1110",     "Brute Force",
                                 tactic="credential-access", is_sub=False, parent=None),
    "T1071.004": _make_technique("T1071.004", "DNS",
                                 tactic="command-and-control", is_sub=True, parent="T1071",
                                 platforms=["windows", "linux", "macos"]),
}


@pytest.fixture(autouse=True)
def inject_cache():
    """Load sample cache before each test, clean up after."""
    override_attck_cache(SAMPLE_CACHE.copy())
    yield
    override_attck_cache({})


# ── get_cache_size ─────────────────────────────────────────────────────────────

def test_cache_size_matches_injected_data():
    assert get_cache_size() == len(SAMPLE_CACHE)

def test_empty_cache_has_size_zero():
    override_attck_cache({})
    assert get_cache_size() == 0


# ── get_technique ──────────────────────────────────────────────────────────────

def test_get_technique_returns_correct_object():
    t = get_technique("T1059.001")
    assert t is not None
    assert t.id   == "T1059.001"
    assert t.name == "PowerShell"

def test_get_technique_returns_none_for_unknown_id():
    assert get_technique("T9999.999") is None

def test_get_technique_returns_none_when_cache_empty():
    override_attck_cache({})
    assert get_technique("T1059.001") is None

def test_get_technique_parent_technique():
    t = get_technique("T1059")
    assert t is not None
    assert t.is_subtechnique is False
    assert t.parent_id is None

def test_get_technique_subtechnique_has_parent():
    t = get_technique("T1059.001")
    assert t.is_subtechnique is True
    assert t.parent_id == "T1059"

def test_get_technique_preserves_platforms():
    t = get_technique("T1071.004")
    assert "linux" in t.platforms
    assert "macos" in t.platforms


# ── get_all_technique_ids ──────────────────────────────────────────────────────

def test_get_all_ids_returns_sorted_list():
    ids = get_all_technique_ids()
    assert ids == sorted(ids)

def test_get_all_ids_count_matches_cache():
    ids = get_all_technique_ids()
    assert len(ids) == len(SAMPLE_CACHE)

def test_get_all_ids_contains_expected_ids():
    ids = get_all_technique_ids()
    assert "T1059.001" in ids
    assert "T1003"     in ids
    assert "T1110"     in ids

def test_get_all_ids_empty_when_cache_empty():
    override_attck_cache({})
    assert get_all_technique_ids() == []


# ── validate_technique_id ─────────────────────────────────────────────────────

def test_validate_known_id_returns_true():
    assert validate_technique_id("T1059.001") is True

def test_validate_unknown_id_returns_false():
    assert validate_technique_id("T9999") is False

def test_validate_empty_string_returns_false():
    assert validate_technique_id("") is False

def test_validate_all_sample_ids():
    for tid in SAMPLE_CACHE:
        assert validate_technique_id(tid) is True


# ── get_tactic_order ──────────────────────────────────────────────────────────

def test_tactic_order_starts_with_reconnaissance():
    order = get_tactic_order()
    assert order[0] == "reconnaissance"

def test_tactic_order_ends_with_impact():
    order = get_tactic_order()
    assert order[-1] == "impact"

def test_tactic_order_contains_all_14_tactics():
    order = get_tactic_order()
    assert len(order) == 14

def test_tactic_order_returns_copy_not_reference():
    order1 = get_tactic_order()
    order1.append("fake-tactic")
    order2 = get_tactic_order()
    assert "fake-tactic" not in order2

def test_tactic_order_contains_lateral_movement():
    assert "lateral-movement" in get_tactic_order()

def test_tactic_order_execution_before_persistence():
    order = get_tactic_order()
    assert order.index("execution") < order.index("persistence")

def test_tactic_order_initial_access_before_execution():
    order = get_tactic_order()
    assert order.index("initial-access") < order.index("execution")


# ── override_attck_cache ──────────────────────────────────────────────────────

def test_override_replaces_existing_cache():
    new_tech = _make_technique("T9000", "Custom technique")
    override_attck_cache({"T9000": new_tech})
    assert get_cache_size() == 1
    assert get_technique("T9000") is not None
    assert get_technique("T1059.001") is None  # old data gone

def test_override_with_empty_dict_clears_cache():
    override_attck_cache({})
    assert get_cache_size() == 0
    assert get_all_technique_ids() == []
