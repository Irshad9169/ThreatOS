from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.database import get_db
from threatos.core.dependencies import get_current_user, require_engineer
from threatos.models.user import User
from threatos.services.audit_service import Action, Resource, audit
from threatos.services.nmap_service import (
    SCAN_FLAGS, create_scan, get_scan, list_scans, run_scan,
)

router = APIRouter()

class ScanIn(BaseModel):
    target:       str = Field(..., min_length=1, max_length=255)
    scan_type:    str = "quick"
    requested_by: str | None = None
    timeout:      int = Field(default=300, ge=10, le=3600)

def _out(s):
    return {"id": s.id, "target": s.target, "scan_type": s.scan_type,
            "status": s.status, "hosts_up": s.hosts_up, "hosts_down": s.hosts_down,
            "open_ports": s.open_ports or [], "os_guesses": s.os_guesses or [],
            "duration_s": s.duration_s, "error_detail": s.error_detail,
            "started_at":  s.started_at.isoformat()  if s.started_at  else None,
            "finished_at": s.finished_at.isoformat() if s.finished_at else None}

@router.post("", status_code=201)
async def create_and_run(
    body: ScanIn, request: Request,
    current_user: User = Depends(require_engineer),
    db: AsyncSession = Depends(get_db),
):
    try:
        scan = await create_scan(db, body.target, scan_type=body.scan_type,
                                  requested_by=current_user.username)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    result = await run_scan(db, scan.id, timeout=body.timeout)
    await audit(db, Action.SCAN_RUN, Resource.SCAN,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=scan.id,
                detail=f"'{current_user.username}' ran {body.scan_type} scan on '{body.target}' — "
                       f"status={result.status} hosts_up={result.hosts_up} "
                       f"open_ports={len(result.open_ports or [])}",
                request=request)
    return _out(result)

@router.post("/create", status_code=201)
async def create_pending(
    body: ScanIn, request: Request,
    current_user: User = Depends(require_engineer),
    db: AsyncSession = Depends(get_db),
):
    try:
        scan = await create_scan(db, body.target, scan_type=body.scan_type,
                                  requested_by=current_user.username)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    await audit(db, Action.SCAN_CREATE, Resource.SCAN,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=scan.id,
                detail=f"'{current_user.username}' created pending {body.scan_type} scan for '{body.target}'",
                request=request)
    return _out(scan)

@router.post("/{scan_id}/run")
async def run_existing(
    scan_id: str, request: Request,
    timeout: int = Query(default=300, ge=10, le=3600),
    current_user: User = Depends(require_engineer),
    db: AsyncSession = Depends(get_db),
):
    try:
        result = await run_scan(db, scan_id, timeout=timeout)
    except ValueError as exc:
        msg  = str(exc)
        code = 404 if "not found" in msg else 422
        raise HTTPException(status_code=code, detail=msg)
    await audit(db, Action.SCAN_RUN, Resource.SCAN,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=scan_id,
                detail=f"'{current_user.username}' executed scan {scan_id[:8]} on '{result.target}' — "
                       f"status={result.status}",
                request=request)
    return _out(result)

@router.get("")
async def list_scans_route(
    target:      str | None = Query(None),
    scan_status: str | None = Query(None, alias="status"),
    limit:  int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    scans = await list_scans(db, target=target, status=scan_status,
                              limit=limit, offset=offset)
    return [_out(s) for s in scans]

@router.get("/{scan_id}")
async def get_scan_route(
    scan_id: str,
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    scan = await get_scan(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _out(scan)
