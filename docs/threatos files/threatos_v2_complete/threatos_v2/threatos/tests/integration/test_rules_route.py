"""
tests/integration/test_rules_route.py
───────────────────────────────────────
Integration tests for GET/POST /api/rules routes.
Uses real FastAPI app with SQLite in-memory via conftest fixtures.
"""
import pytest
from httpx import AsyncClient

VALID_RULE = {
    "name":          "PowerShell encoded command",
    "technique_id":  "T1059.001",
    "tactic":        "execution",
    "severity":      7,
    "confidence":    0.85,
    "log_sources":   ["winlog", "json"],
    "platforms":     ["windows"],
    "tags":          ["attack.t1059.001"],
    "detection_ast": {
        "type": "and",
        "children": [
            {"type": "field_match", "field": "process",
             "operator": "contains", "value": "powershell"},
            {"type": "field_match", "field": "command_line",
             "operator": "contains", "value": "-EncodedCommand"},
        ],
    },
}


# ── GET /api/rules ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_rules_returns_empty_initially(test_client: AsyncClient):
    resp = await test_client.get("/api/rules")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_rules_returns_created_rule(test_client: AsyncClient):
    await test_client.post("/api/rules", json=VALID_RULE)
    resp = await test_client.get("/api/rules")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) == 1
    assert rules[0]["name"] == "PowerShell encoded command"


@pytest.mark.asyncio
async def test_list_rules_includes_required_fields(test_client: AsyncClient):
    await test_client.post("/api/rules", json=VALID_RULE)
    resp = await test_client.get("/api/rules")
    rule = resp.json()[0]
    required = {
        "id", "name", "technique_id", "tactic",
        "severity", "confidence", "log_sources",
        "platforms", "tags", "enabled", "trigger_count",
    }
    assert required.issubset(set(rule.keys()))


@pytest.mark.asyncio
async def test_list_rules_enabled_only_by_default(test_client: AsyncClient):
    # Create a rule then disable it
    create_resp = await test_client.post("/api/rules", json=VALID_RULE)
    rule_id = create_resp.json()["id"]
    await test_client.put(f"/api/rules/{rule_id}/toggle")

    # Default listing should return empty (no enabled rules)
    resp = await test_client.get("/api/rules")
    assert resp.json() == []

    # With enabled_only=false we get it back
    resp = await test_client.get("/api/rules?enabled_only=false")
    assert len(resp.json()) == 1


# ── GET /api/rules/{id} ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_rule_by_id(test_client: AsyncClient):
    create_resp = await test_client.post("/api/rules", json=VALID_RULE)
    rule_id = create_resp.json()["id"]

    resp = await test_client.get(f"/api/rules/{rule_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == rule_id

@pytest.mark.asyncio
async def test_get_rule_404_on_missing(test_client: AsyncClient):
    import uuid
    resp = await test_client.get(f"/api/rules/{uuid.uuid4()}")
    assert resp.status_code == 404


# ── POST /api/rules ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_rule_returns_201(test_client: AsyncClient):
    resp = await test_client.post("/api/rules", json=VALID_RULE)
    assert resp.status_code == 201

@pytest.mark.asyncio
async def test_create_rule_response_shape(test_client: AsyncClient):
    resp = await test_client.post("/api/rules", json=VALID_RULE)
    data = resp.json()
    assert data["technique_id"] == "T1059.001"
    assert data["severity"]     == 7
    assert data["confidence"]   == 0.85
    assert data["enabled"]      is True
    assert data["trigger_count"]== 0

@pytest.mark.asyncio
async def test_create_rule_invalid_technique_id_returns_422(
    test_client: AsyncClient,
):
    bad_rule = {**VALID_RULE, "technique_id": "INVALID"}
    resp = await test_client.post("/api/rules", json=bad_rule)
    assert resp.status_code == 422   # Pydantic validation error

@pytest.mark.asyncio
async def test_create_rule_invalid_ast_returns_422(test_client: AsyncClient):
    bad_rule = {**VALID_RULE, "detection_ast": {"type": "totally_wrong"}}
    resp = await test_client.post("/api/rules", json=bad_rule)
    assert resp.status_code == 422

@pytest.mark.asyncio
async def test_create_duplicate_rule_returns_error(test_client: AsyncClient):
    await test_client.post("/api/rules", json=VALID_RULE)
    resp = await test_client.post("/api/rules", json=VALID_RULE)
    # Name must be unique — DB constraint fires
    assert resp.status_code in (409, 500)


# ── PUT /api/rules/{id}/toggle ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_toggle_disables_enabled_rule(test_client: AsyncClient):
    create_resp = await test_client.post("/api/rules", json=VALID_RULE)
    rule_id = create_resp.json()["id"]

    resp = await test_client.put(f"/api/rules/{rule_id}/toggle")
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False

@pytest.mark.asyncio
async def test_toggle_re_enables_disabled_rule(test_client: AsyncClient):
    create_resp = await test_client.post("/api/rules", json=VALID_RULE)
    rule_id = create_resp.json()["id"]

    await test_client.put(f"/api/rules/{rule_id}/toggle")   # disable
    resp = await test_client.put(f"/api/rules/{rule_id}/toggle")   # re-enable
    assert resp.json()["enabled"] is True

@pytest.mark.asyncio
async def test_toggle_404_on_missing_rule(test_client: AsyncClient):
    import uuid
    resp = await test_client.put(f"/api/rules/{uuid.uuid4()}/toggle")
    assert resp.status_code == 404
