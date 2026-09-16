"""
api/routers/assets_router.py
──────────────────────────────
Asset registry routes — thin wrappers over asset_service.py.

Routes:
  GET    /api/assets              filtered list
  GET    /api/assets/{id}         single asset
  POST   /api/assets              create
  POST   /api/assets/upsert       create-or-update by hostname
  PUT    /api/assets/{id}/criticality  update criticality tier
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from threatos.core.database import get_db
from threatos.models.asset import VALID_ENVIRONMENTS, Asset
from threatos.services.asset_service import (
    AssetCreate,
    AssetFilters,
    create_asset,
    get_asset_by_id,
    list_assets,
    update_criticality,
    upsert_asset,
)

router = APIRouter()


# ── Request / Response schemas ────────────────────────────────────────────────

class AssetResponse(BaseModel):
    id:           str
    hostname:     str
    criticality:  int
    owner_team:   str | None
    environment:  str
    os_type:      str
    ip_addresses: list[str]
    tags:         list[str]

    model_config = {"from_attributes": True}


class AssetCreateRequest(BaseModel):
    hostname:     str   = Field(..., min_length=1, max_length=255)
    criticality:  int   = Field(default=2, ge=1, le=4)
    owner_team:   str | None = None
    environment:  str   = Field(default="unknown")
    os_type:      str   = Field(default="unknown")
    ip_addresses: list[str] = Field(default_factory=list)
    tags:         list[str] = Field(default_factory=list)

    @field_validator("environment")
    @classmethod
    def validate_env(cls, v: str) -> str:
        if v not in VALID_ENVIRONMENTS:
            raise ValueError(
                f"environment must be one of {VALID_ENVIRONMENTS}"
            )
        return v


class CriticalityUpdateRequest(BaseModel):
    criticality: int = Field(..., ge=1, le=4)


# ── Helper ────────────────────────────────────────────────────────────────────

def _to_response(asset: Asset) -> AssetResponse:
    return AssetResponse(
        id=str(asset.id),
        hostname=asset.hostname,
        criticality=asset.criticality,
        owner_team=asset.owner_team,
        environment=asset.environment,
        os_type=asset.os_type,
        ip_addresses=asset.ip_addresses or [],
        tags=asset.tags or [],
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("", response_model=list[AssetResponse])
async def list_assets_route(
    criticality:   int | None = Query(None, ge=1, le=4),
    environment:   str | None = Query(None),
    owner_team:    str | None = Query(None),
    hostname_like: str | None = Query(None),
    limit:         int        = Query(100, ge=1, le=500),
    offset:        int        = Query(0, ge=0),
    db: AsyncSession           = Depends(get_db),
) -> list[AssetResponse]:
    assets = await list_assets(db, AssetFilters(
        criticality=criticality,
        environment=environment,
        owner_team=owner_team,
        hostname_like=hostname_like,
        limit=limit,
        offset=offset,
    ))
    return [_to_response(a) for a in assets]


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset_route(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
) -> AssetResponse:
    asset = await get_asset_by_id(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _to_response(asset)


@router.post(
    "",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_asset_route(
    body: AssetCreateRequest,
    db: AsyncSession = Depends(get_db),
) -> AssetResponse:
    """
    Create a new asset.
    Returns 409 if the hostname already exists.
    Returns 422 for invalid criticality / environment (Pydantic validates first).
    """
    data = AssetCreate(
        hostname=body.hostname,
        criticality=body.criticality,
        owner_team=body.owner_team,
        environment=body.environment,
        os_type=body.os_type,
        ip_addresses=body.ip_addresses,
        tags=body.tags,
    )
    try:
        asset = await create_asset(db, data)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Asset with hostname '{body.hostname.lower().strip()}' already exists.",
        )
    return _to_response(asset)


@router.post(
    "/upsert",
    response_model=AssetResponse,
    status_code=status.HTTP_200_OK,
)
async def upsert_asset_route(
    body: AssetCreateRequest,
    db: AsyncSession = Depends(get_db),
) -> AssetResponse:
    """
    Create-or-update an asset by hostname.
    Always returns 200 — use the 'created' field in the response
    header X-Created: true/false to tell which happened.
    """
    from fastapi import Response
    data = AssetCreate(
        hostname=body.hostname,
        criticality=body.criticality,
        owner_team=body.owner_team,
        environment=body.environment,
        os_type=body.os_type,
        ip_addresses=body.ip_addresses,
        tags=body.tags,
    )
    asset, _ = await upsert_asset(db, data)
    return _to_response(asset)


@router.put("/{asset_id}/criticality", response_model=AssetResponse)
async def update_criticality_route(
    asset_id: str,
    body: CriticalityUpdateRequest,
    db: AsyncSession = Depends(get_db),
) -> AssetResponse:
    """
    Update an asset's criticality tier.
    Returns 404 if the asset does not exist.
    """
    try:
        asset = await update_criticality(db, asset_id, body.criticality)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _to_response(asset)
