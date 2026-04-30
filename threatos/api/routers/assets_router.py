from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.database import get_db
from threatos.core.dependencies import get_current_user, require_engineer
from threatos.models.asset import VALID_ENVIRONMENTS
from threatos.models.user import User
from threatos.services.asset_service import (
    AssetCreate, AssetFilters, create_asset, delete_asset,
    get_asset_by_id, list_assets, update_criticality, upsert_asset,
)
from threatos.services.audit_service import Action, Resource, audit

router = APIRouter()

class AssetIn(BaseModel):
    hostname:     str  = Field(..., min_length=1, max_length=255)
    criticality:  int  = Field(default=2, ge=1, le=4)
    owner_team:   str | None = None
    environment:  str  = "unknown"
    os_type:      str  = "unknown"
    ip_addresses: list[str] = []
    tags:         list[str] = []
    @field_validator("environment")
    @classmethod
    def validate_env(cls, v):
        if v not in VALID_ENVIRONMENTS:
            raise ValueError(f"environment must be one of {VALID_ENVIRONMENTS}")
        return v

def _out(a):
    return {"id": a.id, "hostname": a.hostname, "criticality": a.criticality,
            "owner_team": a.owner_team, "environment": a.environment,
            "os_type": a.os_type, "ip_addresses": a.ip_addresses or [],
            "tags": a.tags or []}

@router.get("")
async def list_assets_route(
    criticality:   int | None = Query(None, ge=1, le=4),
    environment:   str | None = Query(None),
    hostname_like: str | None = Query(None),
    limit:  int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    assets = await list_assets(db, AssetFilters(
        criticality=criticality, environment=environment,
        hostname_like=hostname_like, limit=limit, offset=offset))
    return [_out(a) for a in assets]

@router.get("/{asset_id}")
async def get_asset(
    asset_id: str,
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    asset = await get_asset_by_id(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _out(asset)

@router.post("", status_code=201)
async def create_asset_route(
    body: AssetIn, request: Request,
    current_user: User = Depends(require_engineer),
    db: AsyncSession = Depends(get_db),
):
    try:
        asset = await create_asset(db, AssetCreate(**body.model_dump()))
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Hostname already exists")
    await audit(db, Action.ASSET_CREATE, Resource.ASSET,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=asset.id,
                detail=f"'{current_user.username}' registered asset '{asset.hostname}' (crit={asset.criticality})",
                changes={"hostname": asset.hostname, "criticality": asset.criticality,
                         "environment": asset.environment},
                request=request)
    return _out(asset)

@router.post("/upsert")
async def upsert_asset_route(
    body: AssetIn, request: Request,
    current_user: User = Depends(require_engineer),
    db: AsyncSession = Depends(get_db),
):
    asset, created = await upsert_asset(db, AssetCreate(**body.model_dump()))
    await audit(db, Action.ASSET_CREATE if created else Action.ASSET_UPDATE,
                Resource.ASSET,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=asset.id,
                detail=f"'{current_user.username}' upserted asset '{asset.hostname}'",
                request=request)
    return _out(asset)

@router.put("/{asset_id}/criticality")
async def update_crit(
    asset_id: str, body: dict, request: Request,
    current_user: User = Depends(require_engineer),
    db: AsyncSession = Depends(get_db),
):
    old = await get_asset_by_id(db, asset_id)
    if not old:
        raise HTTPException(status_code=404, detail="Asset not found")
    old_crit = old.criticality
    new_crit = body.get("criticality", 2)
    try:
        asset = await update_criticality(db, asset_id, new_crit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    await audit(db, Action.ASSET_UPDATE, Resource.ASSET,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=asset_id,
                detail=f"'{current_user.username}' changed criticality of '{old.hostname}': {old_crit} → {new_crit}",
                changes={"criticality": {"from": old_crit, "to": new_crit}},
                request=request)
    return _out(asset)

@router.delete("/{asset_id}", status_code=204)
async def delete_asset_route(
    asset_id: str, request: Request,
    current_user: User = Depends(require_engineer),
    db: AsyncSession = Depends(get_db),
):
    asset = await get_asset_by_id(db, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    hostname = asset.hostname
    deleted  = await delete_asset(db, asset_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Asset not found")
    await audit(db, Action.ASSET_DELETE, Resource.ASSET,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=asset_id,
                detail=f"'{current_user.username}' deleted asset '{hostname}'",
                changes={"hostname": hostname},
                request=request)
