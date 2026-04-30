from __future__ import annotations
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.auth import (
    decode_access_token, get_user_by_api_key, get_user_by_id,
    is_token_blacklisted,
)
from threatos.core.database import get_db
from threatos.models.user import User

bearer_scheme  = HTTPBearer(auto_error=False)
api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    api_key:     str | None                          = Security(api_key_scheme),
    db:          AsyncSession                        = Depends(get_db),
) -> User:
    # Try JWT first
    if credentials and credentials.credentials:
        payload = decode_access_token(credentials.credentials)
        if payload and payload.get("type") == "access":
            # Check blacklist
            jti = payload.get("jti","")
            if jti and await is_token_blacklisted(db, jti):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            user = await get_user_by_id(db, payload.get("sub",""))
            if user and user.is_active:
                return user

    # Try API key
    if api_key:
        user = await get_user_by_api_key(db, api_key)
        if user and user.is_active:
            return user

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )

async def get_current_user_optional(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    api_key:     str | None                          = Security(api_key_scheme),
    db:          AsyncSession                        = Depends(get_db),
) -> User | None:
    try:
        return await get_current_user(credentials, api_key, db)
    except HTTPException:
        return None

def require_role(*roles: str):
    async def _check(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.role}' not permitted. Required: {list(roles)}",
            )
        return user
    return _check

require_analyst  = require_role("analyst", "engineer", "admin")
require_engineer = require_role("engineer", "admin")
require_admin    = require_role("admin")
require_ingest   = require_role("ingest", "engineer", "admin")
