from __future__ import annotations
import json
import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from threatos.models.audit_log import AuditLog

log = logging.getLogger(__name__)

# ── Action constants ───────────────────────────────────────────────────────────
class Action:
    # Auth
    LOGIN          = "login"
    LOGIN_FAILED   = "login_failed"
    LOGOUT         = "logout"
    TOKEN_REFRESH  = "token_refresh"
    PASSWORD_CHANGE= "password_change"
    PASSWORD_RESET = "password_reset"
    # Users
    USER_CREATE    = "user_create"
    USER_UPDATE    = "user_update"
    USER_DEACTIVATE= "user_deactivate"
    USER_ACTIVATE  = "user_activate"
    API_KEY_GEN    = "api_key_generate"
    API_KEY_REVOKE = "api_key_revoke"
    # Rules
    RULE_CREATE    = "rule_create"
    RULE_TOGGLE    = "rule_toggle"
    RULE_DELETE    = "rule_delete"
    # Alerts
    ALERT_STATUS   = "alert_status_update"
    # Assets
    ASSET_CREATE   = "asset_create"
    ASSET_UPDATE   = "asset_update"
    ASSET_DELETE   = "asset_delete"
    # Chains
    CHAIN_CORRELATE= "chain_correlate"
    CHAIN_STATUS   = "chain_status_update"
    # Coverage
    COVERAGE_REFRESH="coverage_refresh"
    # Purple
    PURPLE_VALIDATE= "purple_validate"
    # Scans
    SCAN_CREATE    = "scan_create"
    SCAN_RUN       = "scan_run"
    # Ingest
    EVENT_INGEST   = "event_ingest"
    BATCH_INGEST   = "batch_ingest"
    # Settings
    SETTINGS_UPDATE= "settings_update"

# ── Resource constants ─────────────────────────────────────────────────────────
class Resource:
    AUTH     = "auth"
    USER     = "user"
    RULE     = "rule"
    ALERT    = "alert"
    ASSET    = "asset"
    CHAIN    = "chain"
    COVERAGE = "coverage"
    PURPLE   = "purple"
    SCAN     = "scan"
    INGEST   = "ingest"
    SETTINGS = "settings"

def _get_ip(request: Request | None) -> str | None:
    if not request:
        return None
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None

def _get_ua(request: Request | None) -> str | None:
    if not request:
        return None
    return request.headers.get("User-Agent", "")[:255]

async def audit(
    db:          AsyncSession,
    action:      str,
    resource:    str,
    result:      str        = "success",
    user_id:     str | None = None,
    username:    str | None = None,
    role:        str | None = None,
    resource_id: str | None = None,
    detail:      str | None = None,
    changes:     dict | None= None,
    request:     Request | None = None,
) -> None:
    """
    Write one audit log entry. Never raises — errors are logged but swallowed
    so audit failures never break the main operation.
    """
    try:
        entry = AuditLog(
            timestamp=datetime.now(UTC),
            user_id=user_id,
            username=username,
            role=role,
            action=action,
            resource=resource,
            resource_id=str(resource_id) if resource_id else None,
            detail=detail,
            ip_address=_get_ip(request),
            user_agent=_get_ua(request),
            result=result,
            changes=changes,
        )
        db.add(entry)
        await db.flush()
    except Exception as exc:
        log.error("Failed to write audit log: %s", exc)

async def get_audit_logs(
    db:          AsyncSession,
    username:    str | None = None,
    action:      str | None = None,
    resource:    str | None = None,
    result:      str | None = None,
    limit:       int        = 100,
    offset:      int        = 0,
) -> list[AuditLog]:
    from sqlalchemy import select
    q = select(AuditLog).order_by(AuditLog.timestamp.desc())
    if username: q = q.where(AuditLog.username == username)
    if action:   q = q.where(AuditLog.action   == action)
    if resource: q = q.where(AuditLog.resource  == resource)
    if result:   q = q.where(AuditLog.result    == result)
    q = q.limit(limit).offset(offset)
    result_set = await db.execute(q)
    return list(result_set.scalars().all())
