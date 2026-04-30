from __future__ import annotations
import time
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.database import get_db
from threatos.core.redis_client import get_redis_client
from threatos.detection.rule_engine import get_loaded_rule_count
from threatos.core.attck_kb import get_cache_size
from threatos.services.health_alert_service import get_platform_status

router     = APIRouter()
_start_time = time.time()

@router.get("")
async def health_check(db: AsyncSession = Depends(get_db)):
    """Basic health check — used by load balancers and monitoring."""
    checks = {}
    try:
        from sqlalchemy import text
        await db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error: {exc}"
    try:
        await get_redis_client().ping()
        checks["redis"] = "ok"
    except Exception as exc:
        checks["redis"] = f"error: {exc}"

    rule_count  = get_loaded_rule_count()
    attck_count = get_cache_size()
    checks["rule_engine"] = "ok" if rule_count > 0 else "warning: no rules loaded"
    checks["attck_cache"] = f"ok ({attck_count} techniques)" if attck_count > 0 else "empty"

    has_error   = any("error"   in str(v) for v in checks.values())
    has_warning = any("warning" in str(v) for v in checks.values())
    overall     = "error" if has_error else "warning" if has_warning else "ok"

    return {
        "status":           overall,
        "uptime_seconds":   round(time.time() - _start_time),
        "version":          "0.1.0",
        "components":       checks,
        "rules_loaded":     rule_count,
        "attck_techniques": attck_count,
    }

@router.get("/status")
async def platform_status(db: AsyncSession = Depends(get_db)):
    """
    Full platform status with health alerts and metrics.
    Used by the ThreatOS health dashboard.
    """
    return await get_platform_status(db)
