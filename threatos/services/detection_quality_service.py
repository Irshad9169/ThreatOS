from __future__ import annotations
import time
import uuid
import logging
from datetime import UTC, datetime
from typing import Any
from sqlalchemy import select, func, update
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.models.detection_rule import DetectionRule
from threatos.models.alert import Alert
from threatos.models.rule_metrics import RuleMetrics
from threatos.models.rule_version import RuleVersion
from threatos.detection.rule_ast import evaluate_ast, node_from_dict
from threatos.ingestion.normalizer import NormalizedEvent

log = logging.getLogger(__name__)

# FP rate threshold above which we suggest disabling
FP_RATE_THRESHOLD = 0.80

# ── Rule metrics ──────────────────────────────────────────────────────────────

async def upsert_rule_metrics(db: AsyncSession, rule_id: str,
                               rule_name: str, eval_ms: float,
                               matched: bool) -> None:
    """Update rule performance metrics after each evaluation."""
    try:
        result = await db.execute(
            select(RuleMetrics).where(RuleMetrics.rule_id == rule_id))
        metrics = result.scalar_one_or_none()
        now = datetime.now(UTC)

        if metrics is None:
            metrics = RuleMetrics(
                rule_id=rule_id, rule_name=rule_name,
                total_evals=1, total_matches=1 if matched else 0,
                avg_eval_ms=eval_ms, last_eval_at=now,
                last_match_at=now if matched else None,
            )
            db.add(metrics)
        else:
            metrics.total_evals  += 1
            metrics.last_eval_at  = now
            # Rolling average for eval time
            metrics.avg_eval_ms = (
                (metrics.avg_eval_ms * (metrics.total_evals - 1) + eval_ms)
                / metrics.total_evals
            )
            if matched:
                metrics.total_matches += 1
                metrics.last_match_at  = now
        await db.flush()
    except Exception as exc:
        log.debug("Failed to update rule metrics: %s", exc)

async def record_false_positive(db: AsyncSession, rule_id: str) -> dict:
    """
    Called when an analyst marks an alert as false_positive.
    Increments FP counter and recalculates FP rate.
    Suggests disable if FP rate > threshold.
    """
    result = await db.execute(
        select(RuleMetrics).where(RuleMetrics.rule_id == rule_id))
    metrics = result.scalar_one_or_none()

    if metrics is None:
        return {"rule_id": rule_id, "fp_rate": 0.0, "suggested_disable": False}

    metrics.total_fp += 1
    if metrics.total_matches > 0:
        metrics.fp_rate = round(metrics.total_fp / metrics.total_matches, 4)
    else:
        metrics.fp_rate = 1.0

    metrics.suggested_disable = metrics.fp_rate >= FP_RATE_THRESHOLD
    await db.flush()

    if metrics.suggested_disable:
        log.warning(
            "Rule '%s' has FP rate %.0f%% — consider disabling it",
            metrics.rule_name, metrics.fp_rate * 100,
        )

    return {
        "rule_id":          rule_id,
        "rule_name":        metrics.rule_name,
        "fp_rate":          metrics.fp_rate,
        "total_fp":         metrics.total_fp,
        "total_matches":    metrics.total_matches,
        "suggested_disable":metrics.suggested_disable,
    }

async def get_rule_metrics(db: AsyncSession,
                            sort_by: str = "fp_rate",
                            limit: int = 50) -> list[dict]:
    """Get rule performance metrics sorted by FP rate or eval time."""
    q = select(RuleMetrics)
    if sort_by == "fp_rate":
        q = q.order_by(RuleMetrics.fp_rate.desc())
    elif sort_by == "eval_ms":
        q = q.order_by(RuleMetrics.avg_eval_ms.desc())
    elif sort_by == "matches":
        q = q.order_by(RuleMetrics.total_matches.desc())
    q = q.limit(limit)
    result = await db.execute(q)
    return [{
        "rule_id":           r.rule_id,
        "rule_name":         r.rule_name,
        "total_evals":       r.total_evals,
        "total_matches":     r.total_matches,
        "total_fp":          r.total_fp,
        "fp_rate":           round(r.fp_rate * 100, 1),
        "avg_eval_ms":       round(r.avg_eval_ms, 3),
        "last_match_at":     r.last_match_at.isoformat() if r.last_match_at else None,
        "suggested_disable": r.suggested_disable,
    } for r in result.scalars().all()]

async def get_noisy_rules(db: AsyncSession) -> list[dict]:
    """Rules with FP rate > threshold — candidates for review."""
    result = await db.execute(
        select(RuleMetrics)
        .where(RuleMetrics.fp_rate >= FP_RATE_THRESHOLD / 2)
        .order_by(RuleMetrics.fp_rate.desc())
        .limit(20)
    )
    return [{
        "rule_id":           r.rule_id,
        "rule_name":         r.rule_name,
        "fp_rate":           round(r.fp_rate * 100, 1),
        "total_fp":          r.total_fp,
        "total_matches":     r.total_matches,
        "suggested_disable": r.suggested_disable,
    } for r in result.scalars().all()]

# ── Rule version history ───────────────────────────────────────────────────────

async def snapshot_rule(db: AsyncSession, rule: DetectionRule,
                         change_type: str, changed_by: str | None = None) -> None:
    """Save a version snapshot of a rule before changes."""
    try:
        # Get current version count
        result = await db.execute(
            select(func.count(RuleVersion.id))
            .where(RuleVersion.rule_id == str(rule.id))
        )
        version_num = int(result.scalar() or 0) + 1

        snapshot = {
            "name":         rule.name,
            "technique_id": rule.technique_id,
            "tactic":       rule.tactic,
            "severity":     rule.severity,
            "confidence":   rule.confidence,
            "enabled":      rule.enabled,
            "detection_ast":rule.detection_ast,
            "log_sources":  rule.log_sources,
            "tags":         rule.tags,
            "description":  rule.description,
        }
        version = RuleVersion(
            id=str(uuid.uuid4()),
            rule_id=str(rule.id),
            version=version_num,
            changed_by=changed_by,
            changed_at=datetime.now(UTC),
            change_type=change_type,
            snapshot=snapshot,
        )
        db.add(version)
        await db.flush()
    except Exception as exc:
        log.debug("Failed to snapshot rule: %s", exc)

async def get_rule_history(db: AsyncSession,
                            rule_id: str) -> list[dict]:
    """Get version history for a rule."""
    result = await db.execute(
        select(RuleVersion)
        .where(RuleVersion.rule_id == rule_id)
        .order_by(RuleVersion.version.desc())
    )
    return [{
        "version":     v.version,
        "change_type": v.change_type,
        "changed_by":  v.changed_by,
        "changed_at":  v.changed_at.isoformat(),
        "snapshot":    v.snapshot,
    } for v in result.scalars().all()]

# ── Sigma deduplication ────────────────────────────────────────────────────────

import hashlib, json

def compute_rule_content_hash(detection_ast: dict,
                               technique_id: str) -> str:
    """
    Content-based hash for deduplication.
    Same detection logic + technique = same hash regardless of name.
    """
    canonical = json.dumps(
        {"ast": detection_ast, "tid": technique_id},
        sort_keys=True, separators=(',', ':')
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]

async def find_duplicate_rules(db: AsyncSession) -> list[dict]:
    """Find rules with identical detection logic."""
    result = await db.execute(
        select(DetectionRule).where(DetectionRule.enabled.is_(True))
    )
    rules = result.scalars().all()

    seen: dict[str, list] = {}
    for rule in rules:
        h = compute_rule_content_hash(
            rule.detection_ast or {}, rule.technique_id)
        if h not in seen:
            seen[h] = []
        seen[h].append({
            "id": str(rule.id), "name": rule.name,
            "technique_id": rule.technique_id,
        })

    duplicates = [
        {"content_hash": h, "rules": v}
        for h, v in seen.items() if len(v) > 1
    ]
    return duplicates

# ── Detection testing (dry run) ────────────────────────────────────────────────

async def test_rule_against_recent_events(
    db: AsyncSession,
    detection_ast: dict,
    log_sources: list[str],
    hours_back: int = 24,
    limit: int = 1000,
) -> dict:
    """
    Evaluate a rule AST against recent raw_events without creating alerts.
    Returns match count and sample matches — used before enabling a rule.
    """
    from datetime import timedelta
    from threatos.models.raw_event import RawEvent
    cutoff = datetime.now(UTC) - timedelta(hours=hours_back)

    q = select(RawEvent).where(RawEvent.received_at >= cutoff)
    if log_sources:
        q = q.where(RawEvent.log_source.in_(log_sources))
    q = q.order_by(RawEvent.received_at.desc()).limit(limit)

    result = await db.execute(q)
    events = result.scalars().all()

    try:
        ast_node = node_from_dict(detection_ast)
    except Exception as exc:
        return {"error": f"Invalid detection AST: {exc}",
                "events_tested": 0, "matches": 0, "match_rate": 0.0,
                "sample_matches": []}

    matches = []
    errors  = 0

    for event in events:
        fields = event.normalized or {}
        try:
            start = time.perf_counter()
            matched = evaluate_ast(ast_node, fields)
            elapsed = (time.perf_counter() - start) * 1000

            if matched:
                matches.append({
                    "event_id":    event.id,
                    "received_at": event.received_at.isoformat(),
                    "log_source":  event.log_source,
                    "host":        fields.get("host"),
                    "process":     fields.get("process"),
                    "command_line":fields.get("command_line","")[:100],
                    "eval_ms":     round(elapsed, 3),
                })
        except Exception:
            errors += 1

    total     = len(events)
    match_cnt = len(matches)
    match_rate= round(match_cnt / total * 100, 1) if total else 0.0

    return {
        "events_tested": total,
        "matches":       match_cnt,
        "match_rate":    match_rate,
        "errors":        errors,
        "hours_back":    hours_back,
        "estimated_fp_risk": (
            "high"   if match_rate > 50 else
            "medium" if match_rate > 10 else
            "low"
        ),
        "sample_matches": matches[:10],
    }
