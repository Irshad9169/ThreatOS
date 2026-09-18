"""
tests/unit/test_compliance_service.py
────────────────────────────────────────
Unit tests for services/compliance_service.py — session management and the
audit-log SHA256 hash-chain tamper detection. The hash-chain half had zero
test coverage and turned out to be completely disconnected: AuditLog never
declared prev_hash/entry_hash as mapped columns (migration 006 added them
via ALTER TABLE only), and stamp_audit_entry() was never called from
audit_service.audit() — every audit entry silently got no hash at all, and
GET /api/compliance/audit-integrity would raise AttributeError the moment
it queried AuditLog.entry_hash. Both fixed.

Also switched chain ordering from `timestamp` to a new `seq` column
(migration 010): relying on wall-clock time as a hash-chain ordering key
is fragile under back-to-back writes that land on the same tick, so `seq`
removes that ambiguity even though no live tampering-detection failure was
observed from it.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from threatos.models.audit_log import AuditLog
from threatos.models.user_session import UserSession
from threatos.services.audit_service import Action, Resource, audit
from threatos.services.compliance_service import (
    _compute_entry_hash,
    cleanup_expired_sessions,
    create_session,
    get_latest_audit_hash,
    get_user_sessions,
    revoke_all_user_sessions,
    revoke_session,
    stamp_audit_entry,
    update_session_activity,
    verify_audit_chain,
)


# ── Sessions ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_session_persists(db_session):
    session = await create_session(
        db_session, user_id="user-1", jti="jti-1",
        ip_address="1.2.3.4", user_agent="pytest",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    assert session.id
    sessions = await get_user_sessions(db_session, "user-1")
    assert len(sessions) == 1

@pytest.mark.asyncio
async def test_create_session_enforces_concurrent_limit(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.compliance_service.MAX_SESSIONS_PER_USER", 2)
    for i in range(2):
        await create_session(
            db_session, user_id="user-1", jti=f"jti-{i}",
            ip_address=None, user_agent=None,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    # third session should evict the oldest active one
    await create_session(
        db_session, user_id="user-1", jti="jti-2",
        ip_address=None, user_agent=None,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    sessions = await get_user_sessions(db_session, "user-1")
    assert len(sessions) == 2

@pytest.mark.asyncio
async def test_revoke_session_marks_inactive(db_session):
    await create_session(
        db_session, user_id="user-1", jti="jti-x",
        ip_address=None, user_agent=None,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    await revoke_session(db_session, "jti-x")
    sessions = await get_user_sessions(db_session, "user-1")
    assert sessions == []

@pytest.mark.asyncio
async def test_revoke_all_user_sessions_returns_count(db_session):
    for i in range(3):
        await create_session(
            db_session, user_id="user-2", jti=f"jti-{i}",
            ip_address=None, user_agent=None,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    count = await revoke_all_user_sessions(db_session, "user-2")
    assert count == 3
    assert await get_user_sessions(db_session, "user-2") == []

@pytest.mark.asyncio
async def test_update_session_activity_does_not_raise_on_unknown_jti(db_session):
    await update_session_activity(db_session, "nonexistent-jti")   # must not raise

@pytest.mark.asyncio
async def test_cleanup_expired_sessions_deletes_only_expired(db_session):
    await create_session(
        db_session, user_id="user-3", jti="jti-expired",
        ip_address=None, user_agent=None,
        expires_at=datetime.now(UTC) - timedelta(hours=1),
    )
    await create_session(
        db_session, user_id="user-3", jti="jti-active",
        ip_address=None, user_agent=None,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    deleted = await cleanup_expired_sessions(db_session)
    assert deleted == 1
    assert len(await get_user_sessions(db_session, "user-3")) == 1


# ── Audit hash chain ─────────────────────────────────────────────────────────

def _new_entry(action="a", resource="r", resource_id=None) -> AuditLog:
    return AuditLog(
        id=str(uuid.uuid4()), timestamp=datetime.now(UTC),
        action=action, resource=resource, resource_id=resource_id,
        result="success",
    )

@pytest.mark.asyncio
async def test_get_latest_audit_hash_is_genesis_when_empty(db_session):
    assert await get_latest_audit_hash(db_session) == "GENESIS"

@pytest.mark.asyncio
async def test_stamp_audit_entry_sets_both_hashes(db_session):
    entry = _new_entry()
    db_session.add(entry)
    await db_session.flush()
    await stamp_audit_entry(db_session, entry)
    assert entry.prev_hash == "GENESIS"
    assert entry.entry_hash is not None
    assert len(entry.entry_hash) == 32

@pytest.mark.asyncio
async def test_stamp_audit_entry_chains_to_previous_hash(db_session):
    first = _new_entry(action="first")
    db_session.add(first)
    await db_session.flush()
    await stamp_audit_entry(db_session, first)
    await db_session.flush()

    second = _new_entry(action="second")
    db_session.add(second)
    await db_session.flush()
    await stamp_audit_entry(db_session, second)

    assert second.prev_hash == first.entry_hash

@pytest.mark.asyncio
async def test_compute_entry_hash_changes_if_action_changes():
    entry = _new_entry(action="a")
    h1 = _compute_entry_hash(entry, "GENESIS")
    entry.action = "b"
    h2 = _compute_entry_hash(entry, "GENESIS")
    assert h1 != h2

@pytest.mark.asyncio
async def test_verify_audit_chain_ok_when_untampered(db_session):
    entries = []
    for i in range(3):
        entry = _new_entry(action=f"action-{i}")
        db_session.add(entry)
        await db_session.flush()
        await stamp_audit_entry(db_session, entry)
        await db_session.flush()
        # Keep a strong ref: without it the loop variable is the only
        # reference, so SQLAlchemy's identity map (weak-ref based) can
        # GC it between iterations. verify_audit_chain would then reload
        # it fresh from SQLite, whose DateTime(timezone=True) drops
        # tzinfo on round-trip (unlike Postgres) — a spurious mismatch
        # that has nothing to do with real tamper detection.
        entries.append(entry)

    report = await verify_audit_chain(db_session)
    assert report["integrity"] == "ok"
    assert report["total_checked"] == 3
    assert report["broken_entries"] == []

@pytest.mark.asyncio
async def test_verify_audit_chain_detects_tampering(db_session):
    entries = []
    for i in range(3):
        entry = _new_entry(action=f"action-{i}")
        db_session.add(entry)
        await db_session.flush()
        await stamp_audit_entry(db_session, entry)
        await db_session.flush()
        entries.append(entry)

    # Simulate tampering: rewrite a historical entry's action without
    # recomputing its hash — this is exactly what the chain must catch.
    entries[1].action = "tampered-action"
    await db_session.flush()

    report = await verify_audit_chain(db_session)
    assert report["integrity"] == "COMPROMISED"
    assert len(report["broken_entries"]) >= 1
    assert report["broken_entries"][0]["id"] in {e.id for e in entries}

@pytest.mark.asyncio
async def test_audit_helper_actually_stamps_entries(db_session):
    # Regression: audit_service.audit() previously never called
    # stamp_audit_entry at all — every entry written through the normal
    # audit-logging path (used by every router) got no hash chain.
    await audit(db_session, Action.LOGIN, Resource.AUTH,
                user_id="u1", username="alice", role="admin")
    from sqlalchemy import select
    row = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == Action.LOGIN)
    )).scalar_one()
    assert row.entry_hash is not None
    assert row.prev_hash is not None

@pytest.mark.asyncio
async def test_audit_helper_chains_across_multiple_calls(db_session):
    await audit(db_session, Action.LOGIN, Resource.AUTH, username="a")
    await audit(db_session, Action.LOGOUT, Resource.AUTH, username="a")

    from sqlalchemy import select
    rows = (await db_session.execute(
        select(AuditLog).order_by(AuditLog.timestamp.asc())
    )).scalars().all()
    assert len(rows) == 2
    assert rows[1].prev_hash == rows[0].entry_hash
