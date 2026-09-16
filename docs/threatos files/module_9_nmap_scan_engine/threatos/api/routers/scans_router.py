"""
api/routers/scans_router.py
─────────────────────────────
Nmap scan engine routes — thin wrappers over nmap_service.py.

Routes:
  POST /api/scans              create + immediately run a scan
  POST /api/scans/create       create a pending scan (run separately)
  POST /api/scans/{id}/run     run an existing pending scan
  GET  /api/scans              list scans
  GET  /api/scans/{id}         single scan detail

Design note: POST /api/scans is the "fire and forget" endpoint for
the common case. The two-step create/run split is for orchestration
where you want to queue the scan and run it at a controlled time.

Oracle Linux 8: nmap binary lives at /usr/bin/nmap after `dnf install nmap`.
Requires root or CAP_NET_RAW for SYN/UDP scans.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from threatos.core.database import get_db
from threatos.models.scan_result import ScanResult
from threatos.services.nmap_service import SCAN_FLAGS, create_scan, get_scan, list_scans, run_scan

router = APIRouter()


# ── Schemas ───────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target:       str  = Field(..., min_length=1, max_length=255,
                               description="IP, CIDR, hostname, or range")
    scan_type:    str  = Field(default="quick",
                               description=f"One of: {list(SCAN_FLAGS)}")
    requested_by: str | None = None
    timeout:      int  = Field(default=300, ge=10, le=3600,
                               description="Seconds before scan is killed")


class ScanResponse(BaseModel):
    id:           str
    target:       str
    scan_type:    str
    status:       str
    hosts_up:     int
    hosts_down:   int
    open_ports:   list[dict]
    os_guesses:   list[dict]
    duration_s:   float | None
    error_detail: str | None
    started_at:   str | None
    finished_at:  str | None
    requested_by: str | None


def _to_response(scan: ScanResult) -> ScanResponse:
    return ScanResponse(
        id=scan.id,
        target=scan.target,
        scan_type=scan.scan_type,
        status=scan.status,
        hosts_up=scan.hosts_up,
        hosts_down=scan.hosts_down,
        open_ports=scan.open_ports or [],
        os_guesses=scan.os_guesses or [],
        duration_s=scan.duration_s,
        error_detail=scan.error_detail,
        started_at=scan.started_at.isoformat() if scan.started_at else None,
        finished_at=scan.finished_at.isoformat() if scan.finished_at else None,
        requested_by=scan.requested_by,
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create and immediately run a scan",
)
async def create_and_run_scan(
    body: ScanRequest,
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    """
    One-step: create the scan record and execute it synchronously.
    The request will block until Nmap finishes (up to `timeout` seconds).
    Returns the completed (or failed) scan result.
    Raise 422 for unknown scan_type.
    """
    try:
        scan = await create_scan(
            db, body.target, scan_type=body.scan_type,
            requested_by=body.requested_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    result = await run_scan(db, scan.id, timeout=body.timeout)
    return _to_response(result)


@router.post(
    "/create",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a pending scan (does not run it)",
)
async def create_scan_pending(
    body: ScanRequest,
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    """Create the scan record in 'pending' state. Run it with POST /scans/{id}/run."""
    try:
        scan = await create_scan(
            db, body.target, scan_type=body.scan_type,
            requested_by=body.requested_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _to_response(scan)


@router.post(
    "/{scan_id}/run",
    response_model=ScanResponse,
    summary="Execute a pending scan",
)
async def run_existing_scan(
    scan_id: str,
    timeout: int = Query(default=300, ge=10, le=3600),
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    """Run a scan that is in 'pending' state. Returns 404 if not found, 422 if not pending."""
    try:
        result = await run_scan(db, scan_id, timeout=timeout)
    except ValueError as exc:
        msg = str(exc)
        code = 404 if "not found" in msg else 422
        raise HTTPException(status_code=code, detail=msg) from exc
    return _to_response(result)


@router.get(
    "",
    response_model=list[ScanResponse],
    summary="List scans",
)
async def list_scans_route(
    target: str | None = Query(None),
    scan_status: str | None = Query(None, alias="status"),
    limit:  int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> list[ScanResponse]:
    scans = await list_scans(db, target=target, status=scan_status,
                              limit=limit, offset=offset)
    return [_to_response(s) for s in scans]


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    summary="Get a single scan",
)
async def get_scan_route(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    scan = await get_scan(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _to_response(scan)
