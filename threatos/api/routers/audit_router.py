from __future__ import annotations
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.database import get_db
from threatos.core.dependencies import get_current_user, require_engineer
from threatos.models.user import User
from threatos.services.audit_service import get_audit_logs

router = APIRouter()

@router.get("")
async def list_audit_logs(
    username:  str | None = Query(None),
    action:    str | None = Query(None),
    resource:  str | None = Query(None),
    result:    str | None = Query(None),
    limit:  int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: User = Depends(require_engineer),
    db: AsyncSession = Depends(get_db),
):
    logs = await get_audit_logs(db, username=username, action=action,
                                 resource=resource, result=result,
                                 limit=limit, offset=offset)
    return [{
        "id":          l.id,
        "timestamp":   l.timestamp.isoformat(),
        "username":    l.username,
        "role":        l.role,
        "action":      l.action,
        "resource":    l.resource,
        "resource_id": l.resource_id,
        "detail":      l.detail,
        "ip_address":  l.ip_address,
        "result":      l.result,
        "changes":     l.changes,
    } for l in logs]
