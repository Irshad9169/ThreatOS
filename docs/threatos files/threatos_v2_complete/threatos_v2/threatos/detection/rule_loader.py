"""
detection/rule_loader.py
─────────────────────────
Loads enabled detection rules from PostgreSQL into the in-memory engine
at application startup, and reloads on demand.

Called by:
  - main.py lifespan on startup
  - rules_router.py after every create/toggle mutation
  - ingest_worker.py at worker startup

This module is the single entry point for rule loading so there is
never a code path where the engine can run with stale rules.
"""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from threatos.detection.rule_engine import (
    get_loaded_rule_count,
    load_rules_into_engine,
)
from threatos.models.detection_rule import DetectionRule

log = logging.getLogger(__name__)


async def load_rules(db: AsyncSession) -> int:
    """
    Pull all enabled rules from DB, compile ASTs, populate the engine cache.
    Returns the count of successfully loaded rules.
    Logs a warning (not an error) if zero rules are found.
    """
    result = await db.execute(
        select(DetectionRule).where(DetectionRule.enabled.is_(True))
    )
    rules = result.scalars().all()

    rows = [
        {
            "id":           str(r.id),
            "name":         r.name,
            "technique_id": r.technique_id,
            "tactic":       r.tactic,
            "log_sources":  r.log_sources or [],
            "severity":     r.severity,
            "confidence":   r.confidence,
            "detection_ast":r.detection_ast,
            "tags":         r.tags or [],
        }
        for r in rules
    ]

    count = load_rules_into_engine(rows)

    if count == 0:
        log.warning(
            "No enabled detection rules found in DB — "
            "the engine will not generate alerts until rules are created."
        )
    else:
        log.info("Loaded %d detection rules into engine", count)

    return count


async def reload_rules(db: AsyncSession) -> int:
    """
    Reload rules and log the delta from the previous count.
    Used by mutation routes (create, toggle) to keep the engine current.
    """
    before = get_loaded_rule_count()
    after  = await load_rules(db)
    delta  = after - before

    if delta > 0:
        log.info("Rule reload: +%d rules (total %d)", delta, after)
    elif delta < 0:
        log.info("Rule reload: %d rules (total %d)", delta, after)

    return after
