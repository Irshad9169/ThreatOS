"""Integration tests for /api/purple routes."""
from __future__ import annotations
import uuid
import pytest
from httpx import AsyncClient
from threatos.models.detection_rule import DetectionRule


def _rule(technique_id: str, value: str = "powershell") -> DetectionRule:
    return DetectionRule(
        id=uuid.uuid4(), name=f"Rule {technique_id} {uuid.uuid4().hex[:6]}",
        technique_id=technique_id, tactic="execution",
        log_sources=[], platforms=[],
        detection_ast={"type":"field_match","field":"process",
                       "operator":"contains","value":value},
        severity=7, confidence=0.85, tags=[], enabled=True, trigger_count=0,
    )


PS_EVENT = {"process": "powershell.exe", "command_line": "powershell -enc abc"}


# ── POST /api/purple/validate ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_validate_unknown_technique_returns_unknown(test_client: AsyncClient):
    resp = await test_client.post("/api/purple/validate",
                                   json={"technique_id": "T9999", "emulated_event": {}})
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "unknown"

@pytest.mark.asyncio
async def test_validate_pass_when_rule_fires(test_client: AsyncClient, db_session):
    db_session.add(_rule("T1059.001"))
    await db_session.commit()
    resp = await test_client.post("/api/purple/validate",
                                   json={"technique_id": "T1059.001",
                                         "emulated_event": PS_EVENT})
    assert resp.json()["verdict"] == "pass"
    assert resp.json()["detection_rate"] == 100.0

@pytest.mark.asyncio
async def test_validate_fail_when_rule_misses(test_client: AsyncClient, db_session):
    db_session.add(_rule("T1059.001"))
    await db_session.commit()
    resp = await test_client.post("/api/purple/validate",
                                   json={"technique_id": "T1059.001",
                                         "emulated_event": {"process": "notepad.exe"}})
    assert resp.json()["verdict"] == "fail"

@pytest.mark.asyncio
async def test_validate_response_schema(test_client: AsyncClient):
    resp = await test_client.post("/api/purple/validate",
                                   json={"technique_id": "T9999", "emulated_event": {}})
    data = resp.json()
    required = {"run_id","technique_id","verdict","detection_rate",
                "rules_expected","rules_fired","rules_missed"}
    assert required.issubset(set(data.keys()))


# ── POST /api/purple/validate-chain ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_validate_chain_returns_per_technique(test_client: AsyncClient, db_session):
    for tid in ("T1059.001", "T1003.001"):
        db_session.add(_rule(tid))
    await db_session.commit()
    resp = await test_client.post("/api/purple/validate-chain", json={
        "chain_id":       str(uuid.uuid4()),
        "technique_ids":  ["T1059.001", "T1003.001"],
        "emulated_events":{"T1059.001": PS_EVENT},
    })
    assert resp.status_code == 200
    assert len(resp.json()) == 2

@pytest.mark.asyncio
async def test_validate_chain_verdict_per_technique(test_client: AsyncClient, db_session):
    db_session.add(_rule("T1059.001"))
    await db_session.commit()
    resp = await test_client.post("/api/purple/validate-chain", json={
        "chain_id":       str(uuid.uuid4()),
        "technique_ids":  ["T1059.001", "T9999"],
        "emulated_events":{"T1059.001": PS_EVENT},
    })
    results = {r["technique_id"]: r["verdict"] for r in resp.json()}
    assert results["T1059.001"] == "pass"
    assert results["T9999"]     == "unknown"


# ── GET /api/purple/runs ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_runs_empty_initially(test_client: AsyncClient):
    resp = await test_client.get("/api/purple/runs")
    assert resp.status_code == 200
    assert resp.json() == []

@pytest.mark.asyncio
async def test_runs_returns_after_validation(test_client: AsyncClient):
    await test_client.post("/api/purple/validate",
                            json={"technique_id": "T9999", "emulated_event": {}})
    resp = await test_client.get("/api/purple/runs")
    assert len(resp.json()) == 1

@pytest.mark.asyncio
async def test_runs_filter_by_technique(test_client: AsyncClient):
    for tid in ("T1059.001", "T1003.001"):
        await test_client.post("/api/purple/validate",
                                json={"technique_id": tid, "emulated_event": {}})
    resp = await test_client.get("/api/purple/runs?technique_id=T1059.001")
    assert all(r["technique_id"] == "T1059.001" for r in resp.json())


# ── POST /api/purple/score ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_score_v2_returns_all_components(test_client: AsyncClient):
    resp = await test_client.post("/api/purple/score", json={
        "severity": 7, "confidence": 0.85, "asset_criticality": 2,
        "chain_tactic_count": 3, "is_multi_stage": True,
    })
    assert resp.status_code == 200
    data = resp.json()
    required = {"severity","confidence","asset_criticality","chain_tactic_count",
                "is_multi_stage","base_score","chain_boost","stage_boost","final_score"}
    assert required.issubset(set(data.keys()))

@pytest.mark.asyncio
async def test_score_v2_standalone_equals_base(test_client: AsyncClient):
    resp = await test_client.post("/api/purple/score", json={
        "severity": 7, "confidence": 0.85, "asset_criticality": 2,
        "chain_tactic_count": 1, "is_multi_stage": False,
    })
    data = resp.json()
    assert data["final_score"] == data["base_score"]

@pytest.mark.asyncio
async def test_score_v2_chain_elevates_score(test_client: AsyncClient):
    base = (await test_client.post("/api/purple/score", json={
        "severity":7,"confidence":0.85,"asset_criticality":2,
        "chain_tactic_count":1,"is_multi_stage":False,
    })).json()["final_score"]

    chain = (await test_client.post("/api/purple/score", json={
        "severity":7,"confidence":0.85,"asset_criticality":2,
        "chain_tactic_count":5,"is_multi_stage":True,
    })).json()["final_score"]

    assert chain > base
