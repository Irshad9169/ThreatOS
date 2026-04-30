from __future__ import annotations
from datetime import UTC, datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.auth import (
    MAX_LOGIN_ATTEMPTS, LOGIN_LOCKOUT_MIN,
    authenticate_user, blacklist_token, cleanup_old_attempts,
    create_access_token, create_refresh_token,
    create_user, decode_access_token, decode_refresh_token,
    generate_api_key, get_user_by_id, hash_password,
    is_rate_limited, list_users, record_login_attempt, verify_password,
    ACCESS_EXPIRE,
)
from threatos.core.database import get_db
from threatos.core.dependencies import get_current_user, require_admin
from threatos.models.user import VALID_ROLES, User
from threatos.services.audit_service import Action, Resource, audit

router = APIRouter()

# ── Schemas ───────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    expires_in:    int = ACCESS_EXPIRE * 60
    user:          dict

class RefreshRequest(BaseModel):
    refresh_token: str

class UserCreate(BaseModel):
    username:  str        = Field(..., min_length=3, max_length=100)
    email:     str        = Field(..., min_length=5, max_length=255)
    password:  str        = Field(..., min_length=8)
    full_name: str | None = None
    role:      str        = "analyst"

class UserUpdate(BaseModel):
    full_name: str | None  = None
    email:     str | None  = None
    role:      str | None  = None
    is_active: bool | None = None

class PasswordChange(BaseModel):
    current_password: str
    new_password:     str = Field(..., min_length=8)

def _user_out(u: User) -> dict:
    return {
        "id": u.id, "username": u.username, "email": u.email,
        "full_name": u.full_name, "role": u.role, "is_active": u.is_active,
        "created_at": u.created_at.isoformat(),
        "last_login": u.last_login.isoformat() if u.last_login else None,
        "has_api_key": bool(u.api_key),
    }

def _get_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

# ── Auth routes ───────────────────────────────────────────────────────────────
@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request,
                db: AsyncSession = Depends(get_db)):
    ip = _get_ip(request)

    # Rate limit check
    limited, remaining = await is_rate_limited(db, ip)
    if limited:
        await audit(db, Action.LOGIN_FAILED, Resource.AUTH,
                    result="blocked", username=body.username,
                    detail=f"Login blocked — rate limit exceeded for IP {ip}",
                    request=request)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {LOGIN_LOCKOUT_MIN} minutes.",
            headers={"Retry-After": str(LOGIN_LOCKOUT_MIN * 60)},
        )

    # Authenticate
    user = await authenticate_user(db, body.username, body.password)

    # Record attempt
    await record_login_attempt(db, ip, body.username, success=bool(user))

    if not user:
        await audit(db, Action.LOGIN_FAILED, Resource.AUTH,
                    result="failure", username=body.username,
                    detail=f"Failed login for '{body.username}' from {ip} "
                           f"({remaining - 1} attempts remaining)",
                    request=request)
        # Clean up old attempts periodically
        await cleanup_old_attempts(db)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid username or password. "
                   f"{max(0, remaining-1)} attempts remaining before lockout.",
        )

    payload       = {"sub": user.id, "role": user.role, "username": user.username}
    access_token, access_jti   = create_access_token(payload)
    refresh_token, refresh_jti = create_refresh_token(payload)

    await audit(db, Action.LOGIN, Resource.AUTH,
                user_id=user.id, username=user.username, role=user.role,
                detail=f"User '{user.username}' logged in from {ip}",
                request=request)

    return TokenResponse(
        access_token=access_token, refresh_token=refresh_token,
        user=_user_out(user),
    )

@router.post("/logout")
async def logout(request: Request,
                 current_user: User = Depends(get_current_user),
                 db: AsyncSession = Depends(get_db)):
    # Blacklist the current access token
    from fastapi.security import HTTPBearer
    from fastapi import Security
    auth_header = request.headers.get("Authorization","")
    if auth_header.startswith("Bearer "):
        token   = auth_header[7:]
        payload = decode_access_token(token)
        if payload:
            jti        = payload.get("jti","")
            exp        = payload.get("exp", 0)
            expires_at = datetime.fromtimestamp(exp, tz=UTC)
            if jti:
                await blacklist_token(db, jti, current_user.id, expires_at)

    await audit(db, Action.LOGOUT, Resource.AUTH,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role,
                detail=f"User '{current_user.username}' logged out",
                request=request)
    return {"message": "Logged out successfully"}

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token_route(body: RefreshRequest, request: Request,
                               db: AsyncSession = Depends(get_db)):
    payload = decode_refresh_token(body.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user = await get_user_by_id(db, payload.get("sub",""))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    new_payload   = {"sub": user.id, "role": user.role, "username": user.username}
    access_token, _  = create_access_token(new_payload)
    refresh_token, _ = create_refresh_token(new_payload)

    await audit(db, Action.TOKEN_REFRESH, Resource.AUTH,
                user_id=user.id, username=user.username, role=user.role,
                detail="Access token refreshed", request=request)

    return TokenResponse(
        access_token=access_token, refresh_token=refresh_token,
        user=_user_out(user),
    )

@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    return _user_out(current_user)

@router.post("/change-password")
async def change_password(body: PasswordChange, request: Request,
                          current_user: User = Depends(get_current_user),
                          db: AsyncSession = Depends(get_db)):
    if not verify_password(body.current_password, current_user.password_hash):
        await audit(db, Action.PASSWORD_CHANGE, Resource.USER,
                    result="failure", user_id=current_user.id,
                    username=current_user.username, role=current_user.role,
                    detail="Password change failed — wrong current password",
                    request=request)
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    # Blacklist current token — force re-login after password change
    auth_header = request.headers.get("Authorization","")
    if auth_header.startswith("Bearer "):
        token   = auth_header[7:]
        payload = decode_access_token(token)
        if payload:
            jti        = payload.get("jti","")
            exp        = payload.get("exp", 0)
            expires_at = datetime.fromtimestamp(exp, tz=UTC)
            if jti:
                await blacklist_token(db, jti, current_user.id, expires_at)

    current_user.password_hash = hash_password(body.new_password)
    await db.flush()

    await audit(db, Action.PASSWORD_CHANGE, Resource.USER,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role,
                detail=f"'{current_user.username}' changed password — all sessions invalidated",
                request=request)
    return {"message": "Password changed. Please log in again."}

# ── User management ───────────────────────────────────────────────────────────
@router.get("/users")
async def get_users(_: User = Depends(require_admin),
                    db: AsyncSession = Depends(get_db)):
    users = await list_users(db)
    return [_user_out(u) for u in users]

@router.post("/users", status_code=201)
async def create_user_route(body: UserCreate, request: Request,
                             admin: User = Depends(require_admin),
                             db: AsyncSession = Depends(get_db)):
    if body.role not in VALID_ROLES:
        raise HTTPException(status_code=400,
            detail=f"Invalid role. Must be one of: {list(VALID_ROLES)}")
    from sqlalchemy.exc import IntegrityError
    try:
        user = await create_user(db, body.username, body.email,
                                  body.password, body.role, body.full_name)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409,
            detail="Username or email already exists")
    await audit(db, Action.USER_CREATE, Resource.USER,
                user_id=admin.id, username=admin.username, role=admin.role,
                resource_id=user.id,
                detail=f"Admin '{admin.username}' created user '{user.username}' ({user.role})",
                changes={"username": user.username, "role": user.role},
                request=request)
    return _user_out(user)

@router.put("/users/{user_id}")
async def update_user(user_id: str, body: UserUpdate, request: Request,
                      current_user: User = Depends(require_admin),
                      db: AsyncSession = Depends(get_db)):
    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    changes = {}
    if body.full_name  is not None:
        changes["full_name"] = {"from": user.full_name, "to": body.full_name}
        user.full_name = body.full_name
    if body.email is not None:
        changes["email"] = {"from": user.email, "to": body.email}
        user.email = body.email.lower().strip()
    if body.is_active is not None:
        changes["is_active"] = {"from": user.is_active, "to": body.is_active}
        user.is_active = body.is_active
    if body.role is not None:
        if body.role not in VALID_ROLES:
            raise HTTPException(status_code=400,
                detail=f"Invalid role: {body.role!r}")
        if user.role == "admin" and body.role != "admin":
            from sqlalchemy import func, select
            result = await db.execute(
                select(func.count(User.id)).where(
                    User.role == "admin", User.is_active == True))
            if (result.scalar() or 0) <= 1:
                raise HTTPException(status_code=400,
                    detail="Cannot demote the last active admin")
        changes["role"] = {"from": user.role, "to": body.role}
        user.role = body.role
    await db.flush()
    await audit(db, Action.USER_UPDATE, Resource.USER,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=user_id,
                detail=f"Admin '{current_user.username}' updated '{user.username}'",
                changes=changes, request=request)
    return _user_out(user)

@router.post("/users/{user_id}/deactivate")
async def deactivate_user(user_id: str, request: Request,
                           current_user: User = Depends(require_admin),
                           db: AsyncSession = Depends(get_db)):
    if user_id == current_user.id:
        raise HTTPException(status_code=400,
            detail="Cannot deactivate your own account")
    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = False
    await db.flush()
    await audit(db, Action.USER_DEACTIVATE, Resource.USER,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=user_id,
                detail=f"Admin '{current_user.username}' deactivated '{user.username}'",
                request=request)
    return {"message": f"User '{user.username}' deactivated"}

@router.post("/users/{user_id}/activate")
async def activate_user(user_id: str, request: Request,
                         admin: User = Depends(require_admin),
                         db: AsyncSession = Depends(get_db)):
    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = True
    await db.flush()
    await audit(db, Action.USER_ACTIVATE, Resource.USER,
                user_id=admin.id, username=admin.username, role=admin.role,
                resource_id=user_id,
                detail=f"Admin '{admin.username}' activated '{user.username}'",
                request=request)
    return {"message": f"User '{user.username}' activated"}

@router.post("/users/{user_id}/reset-password")
async def reset_password(user_id: str, body: dict, request: Request,
                          admin: User = Depends(require_admin),
                          db: AsyncSession = Depends(get_db)):
    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    new_password = body.get("new_password","")
    if len(new_password) < 8:
        raise HTTPException(status_code=400,
            detail="Password must be at least 8 characters")
    user.password_hash = hash_password(new_password)
    await db.flush()
    await audit(db, Action.PASSWORD_RESET, Resource.USER,
                user_id=admin.id, username=admin.username, role=admin.role,
                resource_id=user_id,
                detail=f"Admin '{admin.username}' reset password for '{user.username}'",
                request=request)
    return {"message": f"Password reset for '{user.username}'"}

@router.post("/users/{user_id}/generate-api-key")
async def generate_api_key_route(user_id: str, request: Request,
                                  admin: User = Depends(require_admin),
                                  db: AsyncSession = Depends(get_db)):
    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    key = generate_api_key()
    user.api_key = key
    await db.flush()
    await audit(db, Action.API_KEY_GEN, Resource.USER,
                user_id=admin.id, username=admin.username, role=admin.role,
                resource_id=user_id,
                detail=f"Admin '{admin.username}' generated API key for '{user.username}'",
                request=request)
    return {"api_key": key,
            "message": "Store this key securely — it will not be shown again",
            "usage":   "X-API-Key: " + key}

@router.delete("/users/{user_id}/api-key")
async def revoke_api_key(user_id: str, request: Request,
                          admin: User = Depends(require_admin),
                          db: AsyncSession = Depends(get_db)):
    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.api_key = None
    await db.flush()
    await audit(db, Action.API_KEY_REVOKE, Resource.USER,
                user_id=admin.id, username=admin.username, role=admin.role,
                resource_id=user_id,
                detail=f"Admin '{admin.username}' revoked API key for '{user.username}'",
                request=request)
    return {"message": "API key revoked"}
