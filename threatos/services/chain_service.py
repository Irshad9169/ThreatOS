from __future__ import annotations
import hashlib, uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.attck_kb import TACTIC_ORDER
from threatos.models.alert import Alert
from threatos.models.attack_chain import CHAIN_STATUSES, AttackChain

@dataclass
class ChainResult:
    chain_id: str; host: str; alert_count: int
    tactic_count: int; is_multi_stage: bool
    risk_score: float; created: bool

@dataclass
class ChainFilters:
    host: str | None = None; status: str | None = None
    is_multi_stage: bool | None = None; min_tactic_count: int = 1
    limit: int = 50; offset: int = 0

def _compute_chain_hash(host: str, technique_ids: list[str]) -> str:
    parts = host.lower() + "|" + "|".join(sorted(technique_ids))
    return hashlib.sha256(parts.encode()).hexdigest()[:64]

def _sort_tactics(tactics: list[str]) -> list[str]:
    def _key(t):
        try: return TACTIC_ORDER.index(t)
        except ValueError: return 999
    return sorted(set(tactics), key=_key)

def _sort_techniques_by_tactic(technique_ids: list[str], tactic_map: dict) -> list[str]:
    def _key(tid):
        try: return TACTIC_ORDER.index(tactic_map.get(tid,""))
        except ValueError: return 999
    return sorted(set(technique_ids), key=_key)

async def correlate_alerts(db: AsyncSession, host: str,
                            window_hours: int = 24) -> ChainResult | None:
    cutoff = datetime.now(UTC) - timedelta(hours=window_hours)
    result = await db.execute(
        select(Alert).where(Alert.entity_host == host, Alert.status == "open",
                            Alert.created_at >= cutoff).order_by(Alert.created_at)
    )
    alerts = result.scalars().all()
    if not alerts: return None
    tactic_map   = {a.technique_id: a.tactic for a in alerts if a.technique_id}
    technique_ids= _sort_techniques_by_tactic([a.technique_id for a in alerts if a.technique_id], tactic_map)
    tactics      = _sort_tactics([a.tactic for a in alerts if a.tactic])
    alert_ids    = [str(a.id) for a in alerts]
    first_seen   = alerts[0].created_at
    last_seen    = alerts[-1].created_at
    duration_s   = max(0, int((last_seen - first_seen).total_seconds()))
    risk_score   = max(a.risk_score for a in alerts)
    tactic_count = len(tactics)
    chain_hash   = _compute_chain_hash(host, technique_ids)
    existing_r   = await db.execute(
        select(AttackChain).where(AttackChain.chain_hash == chain_hash)
    )
    existing = existing_r.scalar_one_or_none()
    if existing:
        existing.alert_ids        = alert_ids
        existing.technique_ids    = technique_ids
        existing.tactics_observed = tactics
        existing.tactic_count     = tactic_count
        existing.risk_score       = risk_score
        existing.last_seen        = last_seen
        existing.duration_seconds = duration_s
        existing.is_multi_stage   = tactic_count >= 3
        await db.flush()
        return ChainResult(chain_id=str(existing.id), host=host.lower(),
            alert_count=len(alerts), tactic_count=tactic_count,
            is_multi_stage=tactic_count>=3, risk_score=risk_score, created=False)
    chain = AttackChain(id=str(uuid.uuid4()), host=host.lower(),
        chain_hash=chain_hash, alert_ids=alert_ids, technique_ids=technique_ids,
        tactics_observed=tactics, tactic_count=tactic_count, risk_score=risk_score,
        first_seen=first_seen, last_seen=last_seen, duration_seconds=duration_s,
        status="open", is_multi_stage=(tactic_count>=3))
    db.add(chain)
    await db.flush()
    return ChainResult(chain_id=chain.id, host=host.lower(),
        alert_count=len(alerts), tactic_count=tactic_count,
        is_multi_stage=(tactic_count>=3), risk_score=risk_score, created=True)

async def get_chain_by_id(db: AsyncSession, chain_id: str) -> AttackChain | None:
    result = await db.execute(select(AttackChain).where(AttackChain.id == chain_id))
    return result.scalar_one_or_none()

async def list_chains(db: AsyncSession, filters: ChainFilters | None = None) -> list[AttackChain]:
    f = filters or ChainFilters()
    q = select(AttackChain).order_by(AttackChain.risk_score.desc(), AttackChain.first_seen.desc())
    if f.host:            q = q.where(AttackChain.host == f.host.lower())
    if f.status:          q = q.where(AttackChain.status == f.status)
    if f.is_multi_stage is not None:
        q = q.where(AttackChain.is_multi_stage.is_(f.is_multi_stage))
    if f.min_tactic_count > 1:
        q = q.where(AttackChain.tactic_count >= f.min_tactic_count)
    q = q.limit(f.limit).offset(f.offset)
    result = await db.execute(q)
    return list(result.scalars().all())

async def update_chain_status(db: AsyncSession, chain_id: str,
                               new_status: str) -> AttackChain | None:
    if new_status not in CHAIN_STATUSES:
        raise ValueError(f"Invalid chain status {new_status!r}")
    result = await db.execute(
        update(AttackChain).where(AttackChain.id == chain_id)
        .values(status=new_status).returning(AttackChain)
    )
    return result.scalar_one_or_none()
