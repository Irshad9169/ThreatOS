"""
services/chain_service.py
──────────────────────────
Attack chain correlation service.

Core algorithm
──────────────
  correlate_alerts(db, host, window_hours=24)
    1. Fetch all open alerts for the host within the time window
    2. Group by (host) — each host gets its own chain
    3. Sort alerts by created_at
    4. Extract unique technique_ids and tactics_observed in kill-chain order
    5. Compute chain_hash = sha256(host + sorted_technique_ids)
    6. Upsert the chain row (update if hash exists, insert if new)
    7. Return ChainResult summary

Correlation is idempotent: running it twice on the same alert set
produces the same chain_hash and updates the existing row.

Query functions
────────────────
  get_chain_by_id(db, chain_id)
  list_chains(db, filters)       — filter by host, status, multi-stage, etc.
  update_chain_status(db, id, status)
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from threatos.core.attck_kb import TACTIC_ORDER
from threatos.models.alert import Alert
from threatos.models.attack_chain import CHAIN_STATUSES, AttackChain


# ── Result / filter dataclasses ───────────────────────────────────────────────

@dataclass
class ChainResult:
    """Returned by correlate_alerts — summary of what was created/updated."""
    chain_id:       str
    host:           str
    alert_count:    int
    tactic_count:   int
    is_multi_stage: bool
    risk_score:     float
    created:        bool    # True = new chain, False = updated existing


@dataclass
class ChainFilters:
    host:          str | None  = None
    status:        str | None  = None
    is_multi_stage:bool | None = None
    min_tactic_count: int      = 1
    limit:         int         = 50
    offset:        int         = 0


# ── Correlation helpers ───────────────────────────────────────────────────────

def _compute_chain_hash(host: str, technique_ids: list[str]) -> str:
    """
    Deterministic fingerprint for a (host, technique set) combination.
    Same alerts always produce the same hash — enables idempotent upsert.
    """
    parts = host.lower() + "|" + "|".join(sorted(technique_ids))
    return hashlib.sha256(parts.encode()).hexdigest()[:64]


def _sort_tactics(tactics: list[str]) -> list[str]:
    """Sort tactics by kill-chain order; unknown tactics go to the end."""
    def _key(t: str) -> int:
        try:
            return TACTIC_ORDER.index(t)
        except ValueError:
            return 999

    return sorted(set(tactics), key=_key)


def _sort_techniques_by_tactic(
    technique_ids: list[str],
    tactic_map: dict[str, str],   # technique_id → tactic
) -> list[str]:
    """Order technique IDs by the kill-chain position of their tactic."""
    def _key(tid: str) -> int:
        tactic = tactic_map.get(tid, "")
        try:
            return TACTIC_ORDER.index(tactic)
        except ValueError:
            return 999

    return sorted(set(technique_ids), key=_key)


# ── Core correlation ──────────────────────────────────────────────────────────

async def correlate_alerts(
    db: AsyncSession,
    host: str,
    window_hours: int = 24,
) -> ChainResult | None:
    """
    Correlate all recent open alerts for `host` into one attack chain.

    Returns None if there are no open alerts for the host in the window.
    Otherwise upserts an AttackChain row and returns a ChainResult.

    Correlation is intentionally coarse in Phase 1:
      - All techniques seen on a host within the window → one chain.
    Phase 2 will split chains on time gaps > N minutes.
    """
    cutoff = datetime.now(UTC) - timedelta(hours=window_hours)

    result = await db.execute(
        select(Alert)
        .where(
            Alert.entity_host == host,
            Alert.status == "open",
            Alert.created_at >= cutoff,
        )
        .order_by(Alert.created_at)
    )
    alerts = result.scalars().all()

    if not alerts:
        return None

    # Build technique and tactic sets
    tactic_map: dict[str, str] = {
        a.technique_id: a.tactic for a in alerts if a.technique_id
    }
    technique_ids = _sort_techniques_by_tactic(
        [a.technique_id for a in alerts if a.technique_id],
        tactic_map,
    )
    tactics_observed = _sort_tactics(
        [a.tactic for a in alerts if a.tactic]
    )

    alert_ids    = [str(a.id) for a in alerts]
    first_seen   = alerts[0].created_at
    last_seen    = alerts[-1].created_at
    duration_s   = max(0, int((last_seen - first_seen).total_seconds()))
    risk_score   = max(a.risk_score for a in alerts)
    tactic_count = len(tactics_observed)
    chain_hash   = _compute_chain_hash(host, technique_ids)

    # Upsert
    existing = await _get_chain_by_hash(db, chain_hash)

    if existing:
        # Update existing chain with latest data
        existing.alert_ids       = alert_ids
        existing.technique_ids   = technique_ids
        existing.tactics_observed= tactics_observed
        existing.tactic_count    = tactic_count
        existing.risk_score      = risk_score
        existing.last_seen       = last_seen
        existing.duration_seconds= duration_s
        existing.is_multi_stage  = tactic_count >= 3
        await db.flush()
        chain_id = str(existing.id)
        created  = False
    else:
        chain = AttackChain(
            id=str(uuid.uuid4()),
            host=host.lower(),
            chain_hash=chain_hash,
            alert_ids=alert_ids,
            technique_ids=technique_ids,
            tactics_observed=tactics_observed,
            tactic_count=tactic_count,
            risk_score=risk_score,
            first_seen=first_seen,
            last_seen=last_seen,
            duration_seconds=duration_s,
            status="open",
            is_multi_stage=(tactic_count >= 3),
        )
        db.add(chain)
        await db.flush()
        chain_id = chain.id
        created  = True

    return ChainResult(
        chain_id=chain_id,
        host=host.lower(),
        alert_count=len(alerts),
        tactic_count=tactic_count,
        is_multi_stage=(tactic_count >= 3),
        risk_score=risk_score,
        created=created,
    )


# ── Queries ───────────────────────────────────────────────────────────────────

async def _get_chain_by_hash(
    db: AsyncSession, chain_hash: str
) -> AttackChain | None:
    result = await db.execute(
        select(AttackChain).where(AttackChain.chain_hash == chain_hash)
    )
    return result.scalar_one_or_none()


async def get_chain_by_id(
    db: AsyncSession, chain_id: str
) -> AttackChain | None:
    result = await db.execute(
        select(AttackChain).where(AttackChain.id == chain_id)
    )
    return result.scalar_one_or_none()


async def list_chains(
    db: AsyncSession,
    filters: ChainFilters | None = None,
) -> list[AttackChain]:
    """
    Return chains ordered by risk_score DESC then first_seen DESC.
    """
    f = filters or ChainFilters()
    q = (
        select(AttackChain)
        .order_by(AttackChain.risk_score.desc(), AttackChain.first_seen.desc())
    )

    if f.host:
        q = q.where(AttackChain.host == f.host.lower())
    if f.status:
        q = q.where(AttackChain.status == f.status)
    if f.is_multi_stage is not None:
        q = q.where(AttackChain.is_multi_stage.is_(f.is_multi_stage))
    if f.min_tactic_count > 1:
        q = q.where(AttackChain.tactic_count >= f.min_tactic_count)

    q = q.limit(f.limit).offset(f.offset)
    result = await db.execute(q)
    return list(result.scalars().all())


async def update_chain_status(
    db: AsyncSession,
    chain_id: str,
    new_status: str,
) -> AttackChain | None:
    """Update status. Raises ValueError for invalid status values."""
    if new_status not in CHAIN_STATUSES:
        raise ValueError(
            f"Invalid chain status {new_status!r}. "
            f"Must be one of: {CHAIN_STATUSES}"
        )
    result = await db.execute(
        update(AttackChain)
        .where(AttackChain.id == chain_id)
        .values(status=new_status)
        .returning(AttackChain)
    )
    return result.scalar_one_or_none()
