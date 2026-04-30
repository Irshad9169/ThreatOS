from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.database import get_db
from threatos.core.dependencies import get_current_user, require_admin, require_engineer
from threatos.models.user import User
from threatos.services.audit_service import audit, Action, Resource
from threatos.services.compliance_service import (
    approve_rule_change, get_user_sessions, list_change_requests,
    reject_rule_change, request_rule_change, revoke_all_user_sessions,
    revoke_session, verify_audit_chain,
)

router = APIRouter()

class RuleChangeIn(BaseModel):
    rule_id:      str | None = None
    change_type:  str
    proposed_ast: dict | None = None
    reason:       str | None  = None

class ReviewIn(BaseModel):
    review_note: str | None = None

# ── Sessions ──────────────────────────────────────────────────────────────────

@router.get("/sessions")
async def my_sessions(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all active sessions for the current user."""
    return await get_user_sessions(db, current_user.id)

@router.get("/sessions/{user_id}")
async def user_sessions(
    user_id: str,
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Admin: list all active sessions for any user."""
    return await get_user_sessions(db, user_id)

@router.delete("/sessions/{session_id}")
async def revoke_session_route(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke a specific session (force logout that device)."""
    from threatos.models.user_session import UserSession
    from sqlalchemy import select
    result = await db.execute(
        select(UserSession).where(UserSession.id == session_id))
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    # Users can only revoke their own sessions; admins can revoke any
    if session.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Cannot revoke another user's session")
    await revoke_session(db, session.jti)
    await audit(db, "session_revoke", Resource.USER,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=session_id,
                detail=f"Session {session_id[:8]} revoked by {current_user.username}")
    return {"message": "Session revoked"}

@router.post("/sessions/revoke-all/{user_id}")
async def revoke_all_sessions(
    user_id: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Admin: force logout all sessions for a user."""
    count = await revoke_all_user_sessions(db, user_id)
    await audit(db, "session_revoke_all", Resource.USER,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=user_id,
                detail=f"Admin '{current_user.username}' revoked all {count} sessions for user {user_id}")
    return {"message": f"Revoked {count} active sessions"}

# ── Audit integrity ────────────────────────────────────────────────────────────

@router.get("/audit-integrity")
async def check_audit_integrity(
    limit: int = Query(1000, ge=10, le=10000),
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """
    Verify audit log hash chain integrity.
    Detects any tampering with historical audit records.
    """
    return await verify_audit_chain(db, limit=limit)

# ── Rule change management ────────────────────────────────────────────────────

@router.get("/rule-changes")
async def list_changes(
    status: str | None = Query(None),
    limit:  int        = Query(50, ge=1, le=200),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List rule change requests."""
    return await list_change_requests(db, status=status, limit=limit)

@router.post("/rule-changes", status_code=201)
async def submit_change(
    body: RuleChangeIn,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Submit a rule change request for admin approval."""
    req = await request_rule_change(
        db, rule_id=body.rule_id,
        requested_by=current_user.username,
        change_type=body.change_type,
        proposed_ast=body.proposed_ast,
        reason=body.reason,
    )
    await audit(db, "rule_change_requested", Resource.RULE,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=req.id,
                detail=f"'{current_user.username}' requested {body.change_type} "
                       f"for rule {body.rule_id or 'new'}: {body.reason}")
    return {
        "id":          req.id,
        "status":      req.status,
        "change_type": req.change_type,
        "message":     "Change request submitted — pending admin approval",
    }

@router.post("/rule-changes/{request_id}/approve")
async def approve_change(
    request_id: str,
    body: ReviewIn,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Admin: approve a rule change request."""
    req = await approve_rule_change(db, request_id,
                                     reviewed_by=current_user.username,
                                     review_note=body.review_note)
    if not req:
        raise HTTPException(status_code=404,
            detail="Request not found or not in pending state")
    await audit(db, "rule_change_approved", Resource.RULE,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=request_id,
                detail=f"Admin '{current_user.username}' approved rule change {request_id[:8]}")
    return {"id": req.id, "status": req.status,
            "message": "Change request approved"}

@router.post("/rule-changes/{request_id}/reject")
async def reject_change(
    request_id: str,
    body: ReviewIn,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Admin: reject a rule change request."""
    req = await reject_rule_change(db, request_id,
                                    reviewed_by=current_user.username,
                                    review_note=body.review_note)
    if not req:
        raise HTTPException(status_code=404,
            detail="Request not found or not in pending state")
    await audit(db, "rule_change_rejected", Resource.RULE,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=request_id,
                detail=f"Admin '{current_user.username}' rejected rule change "
                       f"{request_id[:8]}: {body.review_note}")
    return {"id": req.id, "status": req.status,
            "message": "Change request rejected"}
