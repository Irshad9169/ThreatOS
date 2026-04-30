from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.database import get_db
from threatos.core.dependencies import require_admin, require_engineer
from threatos.models.user import User
from threatos.services.retention_service import (
    estimate_days_until_full, get_table_sizes, run_retention,
)

router = APIRouter()

@router.get("/sizes")
async def table_sizes(
    _: User = Depends(require_engineer),
    db: AsyncSession = Depends(get_db),
):
    """Current table sizes and row counts."""
    return await get_table_sizes(db)

@router.get("/estimate")
async def disk_estimate(
    _: User = Depends(require_engineer),
    db: AsyncSession = Depends(get_db),
):
    """Estimate days until disk fills based on current growth rate."""
    return await estimate_days_until_full(db)

@router.post("/run")
async def run_retention_now(
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Manually trigger retention — admin only."""
    deleted = await run_retention(db)
    return {"message": "Retention run complete", "deleted": deleted}
