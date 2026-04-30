from __future__ import annotations
from datetime import UTC, datetime
from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.database import get_db
from threatos.core.dependencies import get_current_user, require_engineer
from threatos.models.user import User
from threatos.services.report_service import generate_pdf_report, gather_report_data

router = APIRouter()

@router.get("/data")
async def get_report_data(
    days: int = Query(7, ge=1, le=90),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return report data as JSON — used by the UI preview."""
    return await gather_report_data(db, days=days)

@router.get("/pdf")
async def download_pdf_report(
    days: int = Query(7, ge=1, le=90),
    _: User = Depends(require_engineer),
    db: AsyncSession = Depends(get_db),
):
    """Generate and stream a PDF report."""
    data     = await gather_report_data(db, days=days)
    pdf_bytes = await generate_pdf_report(data)
    filename = f"threatos_report_{datetime.now(UTC).strftime('%Y%m%d')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
