"""
services/purple_service.py
───────────────────────────
Purple team validation service.

Given a technique and an emulated event, this service:
  1. Identifies which rules target that technique
  2. Runs the rule engine against the emulated event
  3. Records which rules fired and which were expected but missed
  4. Computes a detection_rate and assigns a verdict
  5. Persists the PurpleTeamRun row

Verdicts:
  pass     → all expected rules fired   (detection_rate = 100%)
  partial  → some rules fired           (0% < detection_rate < 100%)
  fail     → no rules fired             (detection_rate = 0%)
  unknown  → no rules configured for this technique

This can also run against an entire AttackChain — validating every
technique in the chain and returning per-technique results.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from threatos.detection.rule_engine import (
    CompiledRule,
    evaluate_ast,
    get_loaded_rule_count,
    load_rules_into_engine,
    node_from_dict,
)
from threatos.ingestion.normalizer import NormalizedEvent
from threatos.models.detection_rule import DetectionRule
from threatos.models.purple_team_run import PurpleTeamRun


# ── Result objects ────────────────────────────────────────────────────────────

@dataclass
class TechniqueValidation:
    technique_id:   str
    rules_expected: list[str]   # rule IDs scoped to this technique
    rules_fired:    list[str]
    rules_missed:   list[str]
    detection_rate: float       # 0.0–100.0
    verdict:        str         # pass / partial / fail / unknown


@dataclass
class PurpleTeamResult:
    run_id:          str
    technique_id:    str
    chain_id:        str | None
    detection_rate:  float
    verdict:         str
    rules_expected:  list[str]
    rules_fired:     list[str]
    rules_missed:    list[str]
    per_technique:   list[TechniqueValidation] = field(default_factory=list)


# ── Core validation ───────────────────────────────────────────────────────────

async def _rules_for_technique(
    db: AsyncSession,
    technique_id: str,
) -> list[DetectionRule]:
    """Fetch all enabled rules that target a specific technique."""
    result = await db.execute(
        select(DetectionRule).where(
            DetectionRule.technique_id == technique_id,
            DetectionRule.enabled.is_(True),
        )
    )
    return list(result.scalars().all())


def _evaluate_rule_against_event(
    rule: DetectionRule,
    event_fields: dict[str, Any],
) -> bool:
    """
    Evaluate a single rule's AST against a flat field dict.
    Returns False on any error — never raises.
    """
    try:
        ast  = node_from_dict(rule.detection_ast)
        return evaluate_ast(ast, event_fields)
    except Exception:
        return False


def _validate_technique(
    technique_id: str,
    rules: list[DetectionRule],
    event_fields: dict[str, Any],
) -> TechniqueValidation:
    """Run all rules for one technique against the emulated event."""
    if not rules:
        return TechniqueValidation(
            technique_id=technique_id,
            rules_expected=[],
            rules_fired=[],
            rules_missed=[],
            detection_rate=0.0,
            verdict="unknown",
        )

    expected = [str(r.id) for r in rules]
    fired    = [
        str(r.id) for r in rules
        if _evaluate_rule_against_event(r, event_fields)
    ]
    missed   = [rid for rid in expected if rid not in fired]

    rate = round(len(fired) / len(expected) * 100.0, 1) if expected else 0.0

    if len(fired) == len(expected):
        verdict = "pass"
    elif fired:
        verdict = "partial"
    elif not expected:
        verdict = "unknown"
    else:
        verdict = "fail"

    return TechniqueValidation(
        technique_id=technique_id,
        rules_expected=expected,
        rules_fired=fired,
        rules_missed=missed,
        detection_rate=rate,
        verdict=verdict,
    )


def _event_to_fields(event_dict: dict[str, Any]) -> dict[str, Any]:
    """Flatten an emulated event dict for AST evaluation."""
    return {k: v for k, v in event_dict.items() if v is not None}


# ── Public API ────────────────────────────────────────────────────────────────

async def run_purple_validation(
    db: AsyncSession,
    technique_id: str,
    emulated_event: dict[str, Any],
    chain_id: str | None = None,
    run_by: str | None = None,
    notes: str | None = None,
) -> PurpleTeamResult:
    """
    Validate detection coverage for a single technique.
    Persists the PurpleTeamRun row and returns the result.
    """
    rules       = await _rules_for_technique(db, technique_id)
    fields      = _event_to_fields(emulated_event)
    validation  = _validate_technique(technique_id, rules, fields)

    run = PurpleTeamRun(
        id=str(uuid.uuid4()),
        technique_id=technique_id,
        chain_id=chain_id,
        emulated_event=emulated_event,
        rules_expected=validation.rules_expected,
        rules_fired=validation.rules_fired,
        rules_missed=validation.rules_missed,
        detection_rate=validation.detection_rate,
        verdict=validation.verdict,
        run_by=run_by,
        notes=notes,
        run_at=datetime.now(UTC),
    )
    db.add(run)
    await db.flush()

    return PurpleTeamResult(
        run_id=run.id,
        technique_id=technique_id,
        chain_id=chain_id,
        detection_rate=validation.detection_rate,
        verdict=validation.verdict,
        rules_expected=validation.rules_expected,
        rules_fired=validation.rules_fired,
        rules_missed=validation.rules_missed,
    )


async def run_chain_validation(
    db: AsyncSession,
    chain_id: str,
    technique_ids: list[str],
    emulated_events: dict[str, dict[str, Any]],   # technique_id → event fields
    run_by: str | None = None,
) -> list[PurpleTeamResult]:
    """
    Validate coverage for every technique in an attack chain.
    Returns one PurpleTeamResult per technique.
    emulated_events is a dict of technique_id → flat field dict.
    Techniques without an emulated event use an empty dict.
    """
    results: list[PurpleTeamResult] = []
    for tid in technique_ids:
        event = emulated_events.get(tid, {})
        result = await run_purple_validation(
            db, tid, event, chain_id=chain_id, run_by=run_by,
        )
        results.append(result)
    return results


async def list_purple_runs(
    db: AsyncSession,
    technique_id: str | None = None,
    chain_id:     str | None = None,
    limit:        int        = 50,
    offset:       int        = 0,
) -> list[PurpleTeamRun]:
    """Return purple team run history, newest first."""
    q = select(PurpleTeamRun).order_by(PurpleTeamRun.run_at.desc())
    if technique_id:
        q = q.where(PurpleTeamRun.technique_id == technique_id)
    if chain_id:
        q = q.where(PurpleTeamRun.chain_id == chain_id)
    q = q.limit(limit).offset(offset)
    result = await db.execute(q)
    return list(result.scalars().all())
