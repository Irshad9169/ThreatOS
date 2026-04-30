from __future__ import annotations
import logging
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.detection.rule_engine import get_loaded_rule_count, load_rules_into_engine
from threatos.models.detection_rule import DetectionRule

log = logging.getLogger(__name__)

async def load_rules(db: AsyncSession) -> int:
    result = await db.execute(
        select(DetectionRule).where(DetectionRule.enabled.is_(True))
    )
    rules = result.scalars().all()
    rows  = [{
        "id": str(r.id), "name": r.name,
        "technique_id": r.technique_id, "tactic": r.tactic,
        "log_sources": r.log_sources or [], "severity": r.severity,
        "confidence": r.confidence, "detection_ast": r.detection_ast,
        "tags": r.tags or [],
    } for r in rules]
    count = load_rules_into_engine(rows)
    if count == 0:
        log.warning("No enabled detection rules found in DB")
    else:
        log.info("Loaded %d detection rules into engine", count)
    return count

async def reload_rules(db: AsyncSession) -> int:
    before = get_loaded_rule_count()
    after  = await load_rules(db)
    log.info("Rule reload: %d -> %d", before, after)
    return after
