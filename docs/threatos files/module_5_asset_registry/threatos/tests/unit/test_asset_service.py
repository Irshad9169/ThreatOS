"""
tests/unit/test_asset_service.py
──────────────────────────────────
Unit tests for asset_service.py.
Uses SQLite in-memory via db_session fixture — no network.
"""
from __future__ import annotations

import pytest
from sqlalchemy import text

from threatos.services.asset_service import (
    AssetCreate,
    AssetFilters,
    create_asset,
    get_asset_by_hostname,
    get_asset_by_id,
    get_criticality_for_host,
    list_assets,
    update_criticality,
    upsert_asset,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _data(
    hostname:    str = "server01.corp",
    criticality: int = 2,
    environment: str = "production",
    owner_team:  str | None = "platform-eng",
    os_type:     str = "linux",
) -> AssetCreate:
    return AssetCreate(
        hostname=hostname,
        criticality=criticality,
        environment=environment,
        owner_team=owner_team,
        os_type=os_type,
    )


# ── create_asset ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_asset_inserts_row(db_session):
    await create_asset(db_session, _data())
    result = await db_session.execute(text("SELECT COUNT(*) FROM assets"))
    assert result.scalar() == 1

@pytest.mark.asyncio
async def test_create_asset_normalises_hostname_to_lowercase(db_session):
    asset = await create_asset(db_session, _data(hostname="SERVER01.CORP"))
    assert asset.hostname == "server01.corp"

@pytest.mark.asyncio
async def test_create_asset_strips_hostname_whitespace(db_session):
    asset = await create_asset(db_session, _data(hostname="  server01  "))
    assert asset.hostname == "server01"

@pytest.mark.asyncio
async def test_create_asset_returns_correct_criticality(db_session):
    asset = await create_asset(db_session, _data(criticality=4))
    assert asset.criticality == 4

@pytest.mark.asyncio
async def test_create_asset_invalid_criticality_raises(db_session):
    with pytest.raises(ValueError, match="criticality"):
        await create_asset(db_session, _data(criticality=5))

@pytest.mark.asyncio
async def test_create_asset_invalid_environment_raises(db_session):
    data = _data()
    data.environment = "INVALID_ENV"
    with pytest.raises(ValueError, match="environment"):
        await create_asset(db_session, data)

@pytest.mark.asyncio
async def test_create_asset_all_valid_criticalities(db_session):
    for tier in (1, 2, 3, 4):
        asset = await create_asset(db_session, _data(
            hostname=f"host-crit-{tier}", criticality=tier
        ))
        assert asset.criticality == tier

@pytest.mark.asyncio
async def test_create_asset_all_valid_environments(db_session):
    from threatos.models.asset import VALID_ENVIRONMENTS
    for i, env in enumerate(VALID_ENVIRONMENTS):
        asset = await create_asset(db_session, _data(
            hostname=f"host-env-{i}", environment=env
        ))
        assert asset.environment == env

@pytest.mark.asyncio
async def test_create_asset_with_ip_addresses(db_session):
    data = _data()
    data.ip_addresses = ["10.0.0.1", "192.168.1.100"]
    asset = await create_asset(db_session, data)
    assert "10.0.0.1" in asset.ip_addresses

@pytest.mark.asyncio
async def test_create_asset_with_tags(db_session):
    data = _data()
    data.tags = ["pci-scope", "dmz"]
    asset = await create_asset(db_session, data)
    assert "pci-scope" in asset.tags

@pytest.mark.asyncio
async def test_create_asset_duplicate_hostname_raises(db_session):
    await create_asset(db_session, _data())
    await db_session.commit()
    from sqlalchemy.exc import IntegrityError
    with pytest.raises(IntegrityError):
        await create_asset(db_session, _data())
        await db_session.flush()


# ── get_asset_by_id ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_asset_by_id_returns_asset(db_session):
    created = await create_asset(db_session, _data())
    fetched = await get_asset_by_id(db_session, created.id)
    assert fetched is not None
    assert fetched.id == created.id

@pytest.mark.asyncio
async def test_get_asset_by_id_returns_none_for_missing(db_session):
    result = await get_asset_by_id(db_session, "nonexistent-id")
    assert result is None


# ── get_asset_by_hostname ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_asset_by_hostname_returns_asset(db_session):
    await create_asset(db_session, _data(hostname="web01"))
    asset = await get_asset_by_hostname(db_session, "web01")
    assert asset is not None
    assert asset.hostname == "web01"

@pytest.mark.asyncio
async def test_get_asset_by_hostname_case_insensitive(db_session):
    await create_asset(db_session, _data(hostname="web01"))
    asset = await get_asset_by_hostname(db_session, "WEB01")
    assert asset is not None

@pytest.mark.asyncio
async def test_get_asset_by_hostname_returns_none_for_missing(db_session):
    result = await get_asset_by_hostname(db_session, "nonexistent")
    assert result is None


# ── list_assets ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_assets_returns_all(db_session):
    for i in range(3):
        await create_asset(db_session, _data(hostname=f"host-{i}"))
    assets = await list_assets(db_session)
    assert len(assets) == 3

@pytest.mark.asyncio
async def test_list_assets_ordered_by_criticality_desc(db_session):
    for tier in (1, 4, 2, 3):
        await create_asset(db_session, _data(
            hostname=f"host-t{tier}", criticality=tier
        ))
    assets = await list_assets(db_session)
    crits  = [a.criticality for a in assets]
    assert crits == sorted(crits, reverse=True)

@pytest.mark.asyncio
async def test_list_assets_filter_by_criticality(db_session):
    await create_asset(db_session, _data(hostname="h1", criticality=4))
    await create_asset(db_session, _data(hostname="h2", criticality=2))
    await create_asset(db_session, _data(hostname="h3", criticality=4))
    assets = await list_assets(db_session, AssetFilters(criticality=4))
    assert len(assets) == 2
    assert all(a.criticality == 4 for a in assets)

@pytest.mark.asyncio
async def test_list_assets_filter_by_environment(db_session):
    await create_asset(db_session, _data(hostname="prod1", environment="production"))
    await create_asset(db_session, _data(hostname="dev1",  environment="development"))
    assets = await list_assets(db_session, AssetFilters(environment="production"))
    assert len(assets) == 1
    assert assets[0].hostname == "prod1"

@pytest.mark.asyncio
async def test_list_assets_filter_by_hostname_substring(db_session):
    await create_asset(db_session, _data(hostname="web-server-01"))
    await create_asset(db_session, _data(hostname="db-server-01"))
    await create_asset(db_session, _data(hostname="cache-01"))
    assets = await list_assets(db_session, AssetFilters(hostname_like="server"))
    assert len(assets) == 2

@pytest.mark.asyncio
async def test_list_assets_pagination(db_session):
    for i in range(5):
        await create_asset(db_session, _data(hostname=f"host-pg-{i}"))
    page1 = await list_assets(db_session, AssetFilters(limit=2, offset=0))
    page2 = await list_assets(db_session, AssetFilters(limit=2, offset=2))
    assert len(page1) == 2
    assert len(page2) == 2
    assert {a.id for a in page1}.isdisjoint({a.id for a in page2})

@pytest.mark.asyncio
async def test_list_assets_empty_returns_empty_list(db_session):
    assets = await list_assets(db_session)
    assert assets == []


# ── update_criticality ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_criticality_changes_tier(db_session):
    asset = await create_asset(db_session, _data(criticality=2))
    await db_session.commit()
    updated = await update_criticality(db_session, asset.id, 4)
    assert updated is not None
    assert updated.criticality == 4

@pytest.mark.asyncio
async def test_update_criticality_returns_none_for_missing(db_session):
    result = await update_criticality(db_session, "nonexistent", 3)
    assert result is None

@pytest.mark.asyncio
async def test_update_criticality_invalid_tier_raises(db_session):
    asset = await create_asset(db_session, _data())
    with pytest.raises(ValueError, match="criticality"):
        await update_criticality(db_session, asset.id, 0)

@pytest.mark.asyncio
async def test_update_criticality_all_valid_tiers(db_session):
    asset = await create_asset(db_session, _data())
    await db_session.commit()
    for tier in (1, 2, 3, 4):
        result = await update_criticality(db_session, asset.id, tier)
        assert result.criticality == tier


# ── upsert_asset ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_upsert_creates_when_new(db_session):
    asset, created = await upsert_asset(db_session, _data())
    assert created is True
    assert asset.hostname == "server01.corp"

@pytest.mark.asyncio
async def test_upsert_updates_when_existing(db_session):
    await create_asset(db_session, _data(criticality=2))
    await db_session.commit()
    updated, created = await upsert_asset(db_session, _data(criticality=4))
    assert created is False
    assert updated.criticality == 4

@pytest.mark.asyncio
async def test_upsert_does_not_create_duplicate(db_session):
    await upsert_asset(db_session, _data())
    await db_session.commit()
    await upsert_asset(db_session, _data(criticality=3))
    result = await db_session.execute(text("SELECT COUNT(*) FROM assets"))
    assert result.scalar() == 1


# ── get_criticality_for_host ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_criticality_returns_correct_tier(db_session):
    await create_asset(db_session, _data(hostname="dc01", criticality=4))
    tier = await get_criticality_for_host(db_session, "dc01")
    assert tier == 4

@pytest.mark.asyncio
async def test_get_criticality_returns_default_for_unknown_host(db_session):
    tier = await get_criticality_for_host(db_session, "totally-unknown-host")
    assert tier == 2

@pytest.mark.asyncio
async def test_get_criticality_returns_default_for_none(db_session):
    tier = await get_criticality_for_host(db_session, None)
    assert tier == 2

@pytest.mark.asyncio
async def test_get_criticality_case_insensitive(db_session):
    await create_asset(db_session, _data(hostname="WIN-DC01", criticality=4))
    # hostname stored as lowercase
    tier = await get_criticality_for_host(db_session, "win-dc01")
    assert tier == 4
