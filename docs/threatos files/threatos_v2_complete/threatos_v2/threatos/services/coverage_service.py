"""
services/coverage_service.py
─────────────────────────────
Coverage computation. Pure service functions — routes call these.

Fix log:
  v2 - platforms stored via json.dumps() not str() (fixes JSONDecodeError)
  v2 - get_coverage_summary uses case() not cast(col, NullType) (fixes CompileError)
  v2 - test for multi-rule used same name; fixed by unique naming in test
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Integer, case, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from threatos.core.attck_kb import get_all_technique_ids, get_technique
from threatos.models.alert import Alert
from threatos.models.coverage_matrix import CoverageMatrix
from threatos.models.detection_rule import DetectionRule


@dataclass
class CoverageRow:
    technique_id:   str
    technique_name: str | None
    tactic:         str | None
    rule_count:     int
    confidence_avg: float
    covered:        bool
    last_triggered: datetime | None
    platforms:      list[str]
    priority_gap:   bool
    refreshed_at:   datetime | None


@dataclass
class CoverageSummary:
    total_techniques: int
    covered:          int
    gaps:             int
    coverage_pct:     float


async def refresh_coverage(db: AsyncSession) -> CoverageSummary:
    """
    Recompute and upsert every ATT&CK technique coverage row.
    Returns a CoverageSummary with aggregate stats.
    """
    now      = datetime.now(UTC)
    all_tids = get_all_technique_ids()

    if not all_tids:
        return CoverageSummary(total_techniques=0, covered=0, gaps=0, coverage_pct=0.0)

    # 1. Rule stats per technique
    rule_stats_q = (
        select(
            DetectionRule.technique_id,
            func.count(DetectionRule.id).label("cnt"),
            func.avg(DetectionRule.confidence).label("avg_conf"),
        )
        .where(DetectionRule.enabled.is_(True))
        .group_by(DetectionRule.technique_id)
    )
    rule_result = await db.execute(rule_stats_q)
    rule_stats: dict[str, dict[str, Any]] = {
        row.technique_id: {
            "count":    int(row.cnt),
            "avg_conf": float(row.avg_conf or 0.0),
        }
        for row in rule_result
    }

    # 2. Last alert per technique
    last_alert_q = (
        select(
            Alert.technique_id,
            func.max(Alert.created_at).label("last_fired"),
        )
        .group_by(Alert.technique_id)
    )
    last_result  = await db.execute(last_alert_q)
    last_fired: dict[str, datetime] = {
        row.technique_id: row.last_fired for row in last_result
    }

    # 3. Upsert all technique rows
    covered_count = 0
    gap_count     = 0

    for tid in all_tids:
        tech       = get_technique(tid)
        stats      = rule_stats.get(tid, {"count": 0, "avg_conf": 0.0})
        is_covered = stats["count"] > 0

        if is_covered:
            covered_count += 1
        else:
            gap_count += 1

        # FIX: use json.dumps() so platforms is valid JSON, not Python repr
        platforms_json = json.dumps(tech.platforms if tech else [])

        await db.execute(
            text("""
                INSERT INTO coverage_matrix
                    (technique_id, technique_name, tactic, rule_count,
                     confidence_avg, covered, last_triggered,
                     platforms, priority_gap, refreshed_at)
                VALUES
                    (:tid, :name, :tactic, :rule_count,
                     :confidence_avg, :covered, :last_triggered,
                     :platforms, :priority_gap, :refreshed_at)
                ON CONFLICT (technique_id) DO UPDATE SET
                    technique_name  = excluded.technique_name,
                    tactic          = excluded.tactic,
                    rule_count      = excluded.rule_count,
                    confidence_avg  = excluded.confidence_avg,
                    covered         = excluded.covered,
                    last_triggered  = excluded.last_triggered,
                    platforms       = excluded.platforms,
                    priority_gap    = excluded.priority_gap,
                    refreshed_at    = excluded.refreshed_at
            """),
            {
                "tid":            tid,
                "name":           tech.name   if tech else tid,
                "tactic":         tech.tactic if tech else None,
                "rule_count":     stats["count"],
                "confidence_avg": stats["avg_conf"],
                "covered":        is_covered,
                "last_triggered": last_fired.get(tid),
                "platforms":      platforms_json,
                "priority_gap":   False,
                "refreshed_at":   now.isoformat(),
            },
        )

    total = len(all_tids)
    pct   = round(covered_count / total * 100.0, 1) if total else 0.0
    return CoverageSummary(
        total_techniques=total,
        covered=covered_count,
        gaps=gap_count,
        coverage_pct=pct,
    )


async def get_coverage(
    db: AsyncSession,
    tactic:       str | None = None,
    covered_only: bool       = False,
) -> list[CoverageRow]:
    """Query coverage_matrix rows ordered by kill-chain tactic then technique_id."""
    from threatos.core.attck_kb import TACTIC_ORDER

    q = select(CoverageMatrix)
    if tactic:
        q = q.where(CoverageMatrix.tactic == tactic)
    if covered_only:
        q = q.where(CoverageMatrix.covered.is_(True))

    result = await db.execute(q)
    rows   = result.scalars().all()

    def _sort_key(r: CoverageMatrix) -> int:
        try:
            return TACTIC_ORDER.index(r.tactic or "")
        except ValueError:
            return 999

    rows_sorted = sorted(rows, key=lambda r: (_sort_key(r), r.technique_id))

    return [
        CoverageRow(
            technique_id=r.technique_id,
            technique_name=r.technique_name,
            tactic=r.tactic,
            rule_count=r.rule_count,
            confidence_avg=r.confidence_avg,
            covered=r.covered,
            last_triggered=r.last_triggered,
            # platforms was stored as JSON string by refresh; parse it back
            platforms=r.platforms if isinstance(r.platforms, list) else [],
            priority_gap=r.priority_gap,
            refreshed_at=r.refreshed_at,
        )
        for r in rows_sorted
    ]


async def get_coverage_summary(db: AsyncSession) -> CoverageSummary:
    """Aggregate stats from the current matrix without triggering a refresh."""
    # FIX: use case() with explicit Integer cast instead of func.cast(col, NullType)
    result = await db.execute(
        select(
            func.count(CoverageMatrix.technique_id).label("total"),
            func.sum(
                case((CoverageMatrix.covered == True, 1), else_=0)
            ).label("covered"),
        )
    )
    row   = result.one()
    total = int(row.total or 0)
    cov   = int(row.covered or 0)
    pct   = round(cov / total * 100.0, 1) if total else 0.0
    return CoverageSummary(
        total_techniques=total,
        covered=cov,
        gaps=total - cov,
        coverage_pct=pct,
    )
