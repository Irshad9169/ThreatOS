from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from threatos.core.dependencies import require_admin
from threatos.core.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.models.user import User
from threatos.services.audit_service import Action, Resource, audit
from threatos.services.settings_service import get_api_key_status, set_api_key

router = APIRouter()

class SetApiKeyIn(BaseModel):
    key_name: str
    value: str

@router.get("/api-keys")
async def api_key_status(_: User = Depends(require_admin)):
    """Whether each managed API key is currently configured. Values are
    never returned — write-only from the UI's perspective."""
    return get_api_key_status()

@router.post("/api-keys")
async def update_api_key(
    body: SetApiKeyIn, request: Request,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """
    Update a managed API key (VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY,
    URLSCAN_API_KEY, URLHAUS_AUTH_KEY). Applies immediately in-memory and
    persists to .env for future restarts. The value itself is never logged
    or echoed back.
    """
    try:
        set_api_key(body.key_name, body.value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    await audit(db, Action.SETTINGS_UPDATE, Resource.SETTINGS,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=body.key_name,
                detail=f"'{current_user.username}' updated API key {body.key_name}",
                request=request)

    return {"key_name": body.key_name, "configured": True}
