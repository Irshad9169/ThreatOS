"""
tests/integration/test_coverage_route.py
──────────────────────────────────────────
Integration tests for POST/GET /api/coverage routes.
Seeds rules and ATT&CK cache, then verifies HTTP responses.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import AsyncClient

from threatos.core.attck_kb import ATTCKTechnique, override_attck_cache
from threatos.models.detection_rule import DetectionRule


# ── Auth: all /api/coverage routes require an authenticated user; the
# refresh route further requires the "engineer" or "admin" role (see
# threatos/api/routers/coverage_router.py — Depends(get_current_user) /
# Depends(require_engineer)). Bypass real JWT/API-key auth by overriding the
# dependency with a real, session-persisted admin user (satisfies both).

@pytest_asyncio.fixture(autouse=True)
async def _authed_user(db_session):
    from threatos.core.dependencies import get_current_user
    from threatos.main import app
    from threatos.models.user import User

    user = User(
        id=str(uuid.uuid4()), username=f"itest-{uuid.uuid4().hex[:8]}",
        email=f"itest-{uuid.uuid4().hex[:8]}@example.com",
        password_hash="not-a-real-hash", role="admin", is_active=True,
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    await db_session.flush()

    async def _override():
        return user

    app.dependency_overrides[get_current_user] = _override
    yield user
    app.dependency_overrides.pop(get_current_user, None)


# ── Fixtures ──────────────────────────────────────────────────────────────────

SAMPLE_KB = {
    "T1059.001": ATTCKTechnique("T1059.001","PowerShell","execution","TA0002",["windows"],"desc"),
    "T1003.001": ATTCKTechnique("T1003.001","LSASS Memory","credential-access","TA0006",["windows"],"desc"),
    "T1110":     ATTCKTechnique("T1110","Brute Force","credential-access","TA0006",[],"desc"),
}


@pytest.fixture(autouse=True)
def inject_kb():
    override_attck_cache(SAMPLE_KB.copy())
    yield
    override_attck_cache({})


def _rule(name: str, technique_id: str, confidence: float = 0.8) -> DetectionRule:
    # NOTE: DetectionRule.id is a String(36) column (models/detection_rule.py),
    # not a native UUID type — must pass a str.
    return DetectionRule(
        id=str(uuid.uuid4()), name=name, technique_id=technique_id,
        tactic="execution", log_sources=[], platforms=[],
        detection_ast={"type":"field_match","field":"process","operator":"exists"},
        severity=5, confidence=confidence, tags=[], enabled=True, trigger_count=0,
    )


# ── POST /api/coverage/refresh ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_refresh_returns_200(test_client: AsyncClient):
    resp = await test_client.post("/api/coverage/refresh")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_refresh_response_has_required_fields(test_client: AsyncClient):
    resp = await test_client.post("/api/coverage/refresh")
    data = resp.json()
    assert "total_techniques" in data
    assert "covered"          in data
    assert "gaps"             in data
    assert "coverage_pct"     in data


@pytest.mark.asyncio
async def test_refresh_total_matches_kb_size(test_client: AsyncClient):
    resp = await test_client.post("/api/coverage/refresh")
    assert resp.json()["total_techniques"] == len(SAMPLE_KB)


@pytest.mark.asyncio
async def test_refresh_all_gaps_when_no_rules(test_client: AsyncClient):
    resp  = await test_client.post("/api/coverage/refresh")
    data  = resp.json()
    assert data["covered"]      == 0
    assert data["gaps"]         == len(SAMPLE_KB)
    assert data["coverage_pct"] == 0.0


@pytest.mark.asyncio
async def test_refresh_counts_covered_correctly(
    test_client: AsyncClient, db_session
):
    db_session.add(_rule("Rule PS", "T1059.001"))
    await db_session.commit()

    resp = await test_client.post("/api/coverage/refresh")
    data = resp.json()
    assert data["covered"]      == 1
    assert data["gaps"]         == 2
    assert data["coverage_pct"] == pytest.approx(33.3, abs=0.2)


@pytest.mark.asyncio
async def test_refresh_is_idempotent(test_client: AsyncClient):
    resp1 = await test_client.post("/api/coverage/refresh")
    resp2 = await test_client.post("/api/coverage/refresh")
    assert resp1.json() == resp2.json()


# ── GET /api/coverage ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_coverage_empty_before_refresh(test_client: AsyncClient):
    resp = await test_client.get("/api/coverage")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_get_coverage_returns_all_after_refresh(test_client: AsyncClient):
    await test_client.post("/api/coverage/refresh")
    resp = await test_client.get("/api/coverage")
    assert len(resp.json()) == len(SAMPLE_KB)


@pytest.mark.asyncio
async def test_get_coverage_row_schema(test_client: AsyncClient):
    await test_client.post("/api/coverage/refresh")
    rows = (await test_client.get("/api/coverage")).json()
    row  = rows[0]
    required = {"technique_id","technique_name","tactic","rule_count",
                "confidence_avg","covered","platforms","priority_gap"}
    assert required.issubset(set(row.keys()))


@pytest.mark.asyncio
async def test_get_coverage_filter_by_tactic(test_client: AsyncClient):
    await test_client.post("/api/coverage/refresh")
    resp = await test_client.get("/api/coverage?tactic=credential-access")
    rows = resp.json()
    assert len(rows) == 2
    assert all(r["tactic"] == "credential-access" for r in rows)


@pytest.mark.asyncio
async def test_get_coverage_covered_only_filter(
    test_client: AsyncClient, db_session
):
    db_session.add(_rule("Rule PS", "T1059.001"))
    await db_session.commit()
    await test_client.post("/api/coverage/refresh")

    resp = await test_client.get("/api/coverage?covered_only=true")
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["technique_id"] == "T1059.001"
    assert rows[0]["covered"] is True


# ── GET /api/coverage/summary ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_summary_zeros_before_refresh(test_client: AsyncClient):
    resp = await test_client.get("/api/coverage/summary")
    assert resp.status_code == 200
    assert resp.json()["total_techniques"] == 0


@pytest.mark.asyncio
async def test_summary_after_refresh(test_client: AsyncClient):
    await test_client.post("/api/coverage/refresh")
    resp = await test_client.get("/api/coverage/summary")
    data = resp.json()
    assert data["total_techniques"] == len(SAMPLE_KB)
    assert data["covered"] + data["gaps"] == data["total_techniques"]
