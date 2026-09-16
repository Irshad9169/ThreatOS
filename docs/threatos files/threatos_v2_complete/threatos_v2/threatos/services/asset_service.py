"""
services/asset_service.py
──────────────────────────
All asset business logic. Pure service functions — no HTTP, no routing.

Functions:
  create_asset(db, data)                 insert a new asset
  get_asset_by_id(db, id)                fetch by PK
  get_asset_by_hostname(db, hostname)    fetch by natural key
  list_assets(db, filters)               filtered list
  update_criticality(db, id, tier)       change criticality (1-4)
  upsert_asset(db, data)                 insert or update on hostname conflict
  get_criticality_for_host(db, hostname) single-value lookup for risk scoring
  AssetCreate / AssetFilters             typed input objects
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from threatos.models.asset import VALID_ENVIRONMENTS, Asset


# ── Input / filter objects ────────────────────────────────────────────────────

@dataclass
class AssetCreate:
    hostname:     str
    criticality:  int         = 2
    owner_team:   str | None  = None
    environment:  str         = "unknown"
    os_type:      str         = "unknown"
    ip_addresses: list        = field(default_factory=list)
    tags:         list        = field(default_factory=list)
    extra:        dict        = field(default_factory=dict)


@dataclass
class AssetFilters:
    criticality:  int | None  = None
    environment:  str | None  = None
    owner_team:   str | None  = None
    hostname_like:str | None  = None   # substring match on hostname
    limit:        int         = 100
    offset:       int         = 0


# ── Validation ────────────────────────────────────────────────────────────────

def _validate_criticality(value: int) -> None:
    if value not in (1, 2, 3, 4):
        raise ValueError(
            f"criticality must be 1, 2, 3, or 4 — got {value!r}"
        )

def _validate_environment(value: str) -> None:
    if value not in VALID_ENVIRONMENTS:
        raise ValueError(
            f"environment {value!r} is not valid. "
            f"Must be one of: {VALID_ENVIRONMENTS}"
        )


# ── Mutations ─────────────────────────────────────────────────────────────────

async def create_asset(db: AsyncSession, data: AssetCreate) -> Asset:
    """
    Insert a new asset.
    Raises ValueError for invalid criticality / environment.
    Raises IntegrityError if the hostname already exists (let caller handle).
    """
    _validate_criticality(data.criticality)
    _validate_environment(data.environment)

    asset = Asset(
        id=str(uuid.uuid4()),
        hostname=data.hostname.lower().strip(),
        criticality=data.criticality,
        owner_team=data.owner_team,
        environment=data.environment,
        os_type=data.os_type,
        ip_addresses=data.ip_addresses,
        tags=data.tags,
        extra=data.extra,
    )
    db.add(asset)
    await db.flush()
    return asset


async def upsert_asset(db: AsyncSession, data: AssetCreate) -> tuple[Asset, bool]:
    """
    Insert if hostname is new, update if it already exists.
    Returns (asset, created) where created=True means a new row was inserted.
    """
    _validate_criticality(data.criticality)
    _validate_environment(data.environment)

    hostname = data.hostname.lower().strip()
    existing = await get_asset_by_hostname(db, hostname)

    if existing:
        existing.criticality  = data.criticality
        existing.owner_team   = data.owner_team
        existing.environment  = data.environment
        existing.os_type      = data.os_type
        existing.ip_addresses = data.ip_addresses
        existing.tags         = data.tags
        existing.extra        = data.extra
        await db.flush()
        return existing, False

    asset = await create_asset(db, data)
    return asset, True


async def update_criticality(
    db: AsyncSession,
    asset_id: str,
    new_criticality: int,
) -> Asset | None:
    """
    Update criticality tier for an asset.
    Returns the updated Asset, or None if not found.
    Raises ValueError for invalid tier values.
    """
    _validate_criticality(new_criticality)

    result = await db.execute(
        update(Asset)
        .where(Asset.id == asset_id)
        .values(criticality=new_criticality)
        .returning(Asset)
    )
    return result.scalar_one_or_none()


# ── Queries ───────────────────────────────────────────────────────────────────

async def get_asset_by_id(db: AsyncSession, asset_id: str) -> Asset | None:
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id)
    )
    return result.scalar_one_or_none()


async def get_asset_by_hostname(db: AsyncSession, hostname: str) -> Asset | None:
    result = await db.execute(
        select(Asset).where(Asset.hostname == hostname.lower().strip())
    )
    return result.scalar_one_or_none()


async def list_assets(
    db: AsyncSession,
    filters: AssetFilters | None = None,
) -> list[Asset]:
    """
    Return a filtered list of assets ordered by criticality DESC then hostname.
    """
    f = filters or AssetFilters()
    q = select(Asset).order_by(Asset.criticality.desc(), Asset.hostname)

    if f.criticality is not None:
        q = q.where(Asset.criticality == f.criticality)
    if f.environment:
        q = q.where(Asset.environment == f.environment)
    if f.owner_team:
        q = q.where(Asset.owner_team == f.owner_team)
    if f.hostname_like:
        q = q.where(Asset.hostname.contains(f.hostname_like.lower()))

    q = q.limit(f.limit).offset(f.offset)
    result = await db.execute(q)
    return list(result.scalars().all())


async def get_criticality_for_host(db: AsyncSession, hostname: str) -> int:
    """
    Single-purpose lookup used by the risk scoring engine.
    Returns the asset's criticality tier, or 2 (default) if unknown.
    This is called on every alert creation — it must be fast.
    """
    if not hostname:
        return 2
    asset = await get_asset_by_hostname(db, hostname)
    return asset.criticality if asset else 2
