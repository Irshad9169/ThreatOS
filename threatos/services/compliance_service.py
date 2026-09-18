from __future__ import annotations
import hashlib
import json
import uuid
import logging
from datetime import UTC, datetime, timedelta
from sqlalchemy import delete, select, update, func
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.models.user_session import UserSession
from threatos.models.audit_log import AuditLog
from threatos.models.rule_change_request import RuleChangeRequest

log = logging.getLogger(__name__)

MAX_SESSIONS_PER_USER = int(__import__('os').environ.get("MAX_SESSIONS_PER_USER", "5"))

# ── Session management ─────────────────────────────────────────────────────────

async def create_session(db: AsyncSession, user_id: str, jti: str,
                          ip_address: str | None, user_agent: str | None,
                          expires_at: datetime) -> UserSession:
    """Create a new session record on login."""
    now = datetime.now(UTC)

    # Enforce concurrent session limit
    result = await db.execute(
        select(func.count(UserSession.id)).where(
            UserSession.user_id  == user_id,
            UserSession.is_active == True,
            UserSession.expires_at > now,
        )
    )
    active_count = int(result.scalar() or 0)

    if active_count >= MAX_SESSIONS_PER_USER:
        # Revoke oldest session
        oldest = await db.execute(
            select(UserSession).where(
                UserSession.user_id  == user_id,
                UserSession.is_active == True,
            ).order_by(UserSession.last_seen_at.asc()).limit(1)
        )
        old = oldest.scalar_one_or_none()
        if old:
            old.is_active = False
            await db.flush()
            log.info("Revoked oldest session for user %s (limit=%d)",
                     user_id, MAX_SESSIONS_PER_USER)

    session = UserSession(
        id=str(uuid.uuid4()), user_id=user_id, jti=jti,
        ip_address=ip_address, user_agent=user_agent[:255] if user_agent else None,
        created_at=now, last_seen_at=now, expires_at=expires_at,
        is_active=True,
    )
    db.add(session)
    await db.flush()
    return session

async def update_session_activity(db: AsyncSession, jti: str) -> None:
    """Update last_seen_at for an active session."""
    try:
        await db.execute(
            update(UserSession).where(UserSession.jti == jti)
            .values(last_seen_at=datetime.now(UTC))
        )
    except Exception as exc:
        log.debug("Failed to update session activity: %s", exc)

async def revoke_session(db: AsyncSession, jti: str) -> None:
    """Revoke a specific session by JTI."""
    await db.execute(
        update(UserSession).where(UserSession.jti == jti)
        .values(is_active=False)
    )
    await db.flush()

async def revoke_all_user_sessions(db: AsyncSession, user_id: str) -> int:
    """Revoke all active sessions for a user. Returns count revoked."""
    result = await db.execute(
        update(UserSession).where(
            UserSession.user_id  == user_id,
            UserSession.is_active == True,
        ).values(is_active=False).returning(UserSession.id)
    )
    count = len(result.fetchall())
    await db.flush()
    return count

async def get_user_sessions(db: AsyncSession, user_id: str) -> list[dict]:
    """List all active sessions for a user."""
    now = datetime.now(UTC)
    result = await db.execute(
        select(UserSession).where(
            UserSession.user_id  == user_id,
            UserSession.is_active == True,
            UserSession.expires_at > now,
        ).order_by(UserSession.last_seen_at.desc())
    )
    return [{
        "id":           s.id,
        "ip_address":   s.ip_address,
        "user_agent":   s.user_agent,
        "created_at":   s.created_at.isoformat(),
        "last_seen_at": s.last_seen_at.isoformat(),
        "expires_at":   s.expires_at.isoformat(),
    } for s in result.scalars().all()]

async def cleanup_expired_sessions(db: AsyncSession) -> int:
    """Delete expired sessions."""
    result = await db.execute(
        delete(UserSession).where(
            UserSession.expires_at < datetime.now(UTC)
        ).returning(UserSession.id)
    )
    return len(result.fetchall())

# ── Audit log hash chain (tamper detection) ────────────────────────────────────

def _compute_entry_hash(entry: AuditLog, prev_hash: str) -> str:
    """
    Compute SHA256 hash of this audit entry chained to previous entry.
    Any modification to a past entry breaks the chain.
    """
    content = json.dumps({
        "id":          entry.id,
        "timestamp":   entry.timestamp.isoformat() if entry.timestamp else "",
        "user_id":     entry.user_id or "",
        "username":    entry.username or "",
        "action":      entry.action,
        "resource":    entry.resource,
        "resource_id": entry.resource_id or "",
        "result":      entry.result,
        "prev_hash":   prev_hash,
    }, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()[:32]

async def get_latest_audit_hash(db: AsyncSession) -> str:
    """Get the hash of the most recent audit entry."""
    result = await db.execute(
        select(AuditLog.entry_hash).where(
            AuditLog.entry_hash.isnot(None)
        ).order_by(AuditLog.seq.desc()).limit(1)
    )
    row = result.scalar_one_or_none()
    return row or "GENESIS"

async def stamp_audit_entry(db: AsyncSession, entry: AuditLog) -> None:
    """Add hash chain to an audit log entry.

    `seq` is assigned here rather than relying on `timestamp` for chain
    ordering — two entries can share the same wall-clock tick under
    back-to-back writes, which `timestamp` can't break ties on
    consistently between this lookup and verify_audit_chain's replay.
    """
    try:
        max_seq   = (await db.execute(select(func.max(AuditLog.seq)))).scalar() or 0
        entry.seq = max_seq + 1
        prev_hash    = await get_latest_audit_hash(db)
        entry_hash   = _compute_entry_hash(entry, prev_hash)
        entry.prev_hash  = prev_hash
        entry.entry_hash = entry_hash
    except Exception as exc:
        log.debug("Failed to stamp audit entry: %s", exc)

async def verify_audit_chain(db: AsyncSession,
                              limit: int = 1000) -> dict:
    """
    Verify the audit log hash chain integrity.
    Returns a report of any tampering detected.
    """
    result = await db.execute(
        select(AuditLog).where(
            AuditLog.entry_hash.isnot(None)
        ).order_by(AuditLog.seq.asc()).limit(limit)
    )
    entries = result.scalars().all()

    total   = len(entries)
    broken  = []
    prev    = "GENESIS"

    for entry in entries:
        expected = _compute_entry_hash(entry, prev)
        if entry.entry_hash != expected:
            broken.append({
                "id":        entry.id,
                "timestamp": entry.timestamp.isoformat(),
                "action":    entry.action,
                "username":  entry.username,
                "stored_hash":   entry.entry_hash,
                "expected_hash": expected,
            })
        prev = entry.entry_hash or prev

    return {
        "total_checked":  total,
        "integrity":      "ok" if not broken else "COMPROMISED",
        "broken_entries": broken,
        "checked_at":     datetime.now(UTC).isoformat(),
    }

# ── Rule change management ────────────────────────────────────────────────────

async def request_rule_change(db: AsyncSession, rule_id: str | None,
                               requested_by: str, change_type: str,
                               proposed_ast: dict | None = None,
                               reason: str | None = None) -> RuleChangeRequest:
    """Submit a rule change request for approval."""
    req = RuleChangeRequest(
        id=str(uuid.uuid4()), rule_id=rule_id,
        requested_by=requested_by,
        requested_at=datetime.now(UTC),
        change_type=change_type,
        proposed_ast=proposed_ast,
        reason=reason, status="pending",
    )
    db.add(req)
    await db.flush()
    return req

async def approve_rule_change(db: AsyncSession, request_id: str,
                               reviewed_by: str,
                               review_note: str | None = None) -> RuleChangeRequest | None:
    """Approve a pending rule change request."""
    result = await db.execute(
        select(RuleChangeRequest).where(RuleChangeRequest.id == request_id))
    req = result.scalar_one_or_none()
    if not req or req.status != "pending":
        return None
    req.status      = "approved"
    req.reviewed_by = reviewed_by
    req.reviewed_at = datetime.now(UTC)
    req.review_note = review_note
    await db.flush()
    return req

async def reject_rule_change(db: AsyncSession, request_id: str,
                              reviewed_by: str,
                              review_note: str | None = None) -> RuleChangeRequest | None:
    """Reject a pending rule change request."""
    result = await db.execute(
        select(RuleChangeRequest).where(RuleChangeRequest.id == request_id))
    req = result.scalar_one_or_none()
    if not req or req.status != "pending":
        return None
    req.status      = "rejected"
    req.reviewed_by = reviewed_by
    req.reviewed_at = datetime.now(UTC)
    req.review_note = review_note
    await db.flush()
    return req

async def list_change_requests(db: AsyncSession,
                                status: str | None = None,
                                limit: int = 50) -> list[dict]:
    """List rule change requests."""
    q = select(RuleChangeRequest).order_by(
        RuleChangeRequest.requested_at.desc())
    if status:
        q = q.where(RuleChangeRequest.status == status)
    q = q.limit(limit)
    result = await db.execute(q)
    return [{
        "id":           r.id,
        "rule_id":      r.rule_id,
        "requested_by": r.requested_by,
        "requested_at": r.requested_at.isoformat(),
        "change_type":  r.change_type,
        "reason":       r.reason,
        "status":       r.status,
        "reviewed_by":  r.reviewed_by,
        "reviewed_at":  r.reviewed_at.isoformat() if r.reviewed_at else None,
        "review_note":  r.review_note,
    } for r in result.scalars().all()]
