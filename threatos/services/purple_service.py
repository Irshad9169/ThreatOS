from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.detection.rule_ast import evaluate_ast, node_from_dict
from threatos.models.detection_rule import DetectionRule
from threatos.models.purple_team_run import PurpleTeamRun

@dataclass
class TechniqueValidation:
    technique_id: str; rules_expected: list[str]
    rules_fired: list[str]; rules_missed: list[str]
    detection_rate: float; verdict: str

@dataclass
class PurpleTeamResult:
    run_id: str; technique_id: str; chain_id: str | None
    detection_rate: float; verdict: str
    rules_expected: list[str]; rules_fired: list[str]; rules_missed: list[str]
    per_technique: list[TechniqueValidation] = field(default_factory=list)

def _eval_rule(rule: DetectionRule, fields: dict) -> bool:
    try: return evaluate_ast(node_from_dict(rule.detection_ast), fields)
    except Exception: return False

def _validate_technique(technique_id: str, rules: list[DetectionRule],
                         fields: dict) -> TechniqueValidation:
    if not rules:
        return TechniqueValidation(technique_id=technique_id,
            rules_expected=[], rules_fired=[], rules_missed=[],
            detection_rate=0.0, verdict="unknown")
    expected = [str(r.id) for r in rules]
    fired    = [str(r.id) for r in rules if _eval_rule(r, fields)]
    missed   = [rid for rid in expected if rid not in fired]
    rate     = round(len(fired)/len(expected)*100.0, 1) if expected else 0.0
    verdict  = "pass" if len(fired)==len(expected) else ("partial" if fired else "fail")
    return TechniqueValidation(technique_id=technique_id,
        rules_expected=expected, rules_fired=fired,
        rules_missed=missed, detection_rate=rate, verdict=verdict)

async def run_purple_validation(db: AsyncSession, technique_id: str,
    emulated_event: dict, chain_id: str | None = None,
    run_by: str | None = None, notes: str | None = None) -> PurpleTeamResult:
    result  = await db.execute(
        select(DetectionRule).where(DetectionRule.technique_id == technique_id,
                                     DetectionRule.enabled.is_(True))
    )
    rules   = list(result.scalars().all())
    fields  = {k: v for k, v in emulated_event.items() if v is not None}
    val     = _validate_technique(technique_id, rules, fields)
    run = PurpleTeamRun(id=str(uuid.uuid4()), technique_id=technique_id,
        chain_id=chain_id, emulated_event=emulated_event,
        rules_expected=val.rules_expected, rules_fired=val.rules_fired,
        rules_missed=val.rules_missed, detection_rate=val.detection_rate,
        verdict=val.verdict, run_by=run_by, notes=notes, run_at=datetime.now(UTC))
    db.add(run)
    await db.flush()
    return PurpleTeamResult(run_id=run.id, technique_id=technique_id,
        chain_id=chain_id, detection_rate=val.detection_rate,
        verdict=val.verdict, rules_expected=val.rules_expected,
        rules_fired=val.rules_fired, rules_missed=val.rules_missed)

async def run_chain_validation(db: AsyncSession, chain_id: str,
    technique_ids: list[str], emulated_events: dict,
    run_by: str | None = None) -> list[PurpleTeamResult]:
    results = []
    for tid in technique_ids:
        r = await run_purple_validation(db, tid,
            emulated_events.get(tid, {}), chain_id=chain_id, run_by=run_by)
        results.append(r)
    return results

async def list_purple_runs(db: AsyncSession, technique_id: str | None = None,
    chain_id: str | None = None, limit: int = 50,
    offset: int = 0) -> list[PurpleTeamRun]:
    q = select(PurpleTeamRun).order_by(PurpleTeamRun.run_at.desc())
    if technique_id: q = q.where(PurpleTeamRun.technique_id == technique_id)
    if chain_id:     q = q.where(PurpleTeamRun.chain_id == chain_id)
    q = q.limit(limit).offset(offset)
    result = await db.execute(q)
    return list(result.scalars().all())
