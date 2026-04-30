from __future__ import annotations
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.database import get_db
from threatos.core.dependencies import get_current_user, require_engineer
from threatos.models.user import User
from threatos.services.detection_quality_service import (
    find_duplicate_rules, get_noisy_rules, get_rule_history,
    get_rule_metrics, record_false_positive,
    test_rule_against_recent_events,
)

router = APIRouter()

class TestRuleIn(BaseModel):
    detection_ast: dict
    log_sources:   list[str] = []
    hours_back:    int        = 24
    limit:         int        = 1000

@router.get("/metrics")
async def rule_metrics(
    sort_by: str = Query("fp_rate", regex="^(fp_rate|eval_ms|matches)$"),
    limit:   int = Query(50, ge=1, le=200),
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Rule performance metrics — eval time, match rate, FP rate."""
    return await get_rule_metrics(db, sort_by=sort_by, limit=limit)

@router.get("/noisy-rules")
async def noisy_rules(
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Rules with high false positive rates — review candidates."""
    return await get_noisy_rules(db)

@router.get("/duplicates")
async def duplicate_rules(
    _: User = Depends(require_engineer),
    db: AsyncSession = Depends(get_db),
):
    """Rules with identical detection logic — deduplication candidates."""
    return await find_duplicate_rules(db)

@router.post("/test")
async def test_rule(
    body: TestRuleIn,
    _: User = Depends(require_engineer),
    db: AsyncSession = Depends(get_db),
):
    """
    Dry-run a detection rule against recent events.
    Returns match count and samples WITHOUT creating alerts.
    Use before enabling a new rule to estimate false positive rate.
    """
    return await test_rule_against_recent_events(
        db,
        detection_ast=body.detection_ast,
        log_sources=body.log_sources,
        hours_back=body.hours_back,
        limit=body.limit,
    )

@router.post("/false-positive/{alert_id}")
async def mark_false_positive(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Mark an alert as false positive.
    Updates the alert status AND increments the rule's FP counter.
    If FP rate exceeds 80%, suggests disabling the rule.
    """
    from threatos.services.alert_service import (
        get_alert_by_id, update_alert_status,
    )
    from threatos.services.audit_service import Action, Resource, audit

    alert = await get_alert_by_id(db, alert_id)
    if not alert:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Alert not found")

    # Update alert status
    await update_alert_status(db, alert_id, "false_positive")

    # Record FP against the rule
    fp_result = {}
    if alert.rule_id:
        fp_result = await record_false_positive(db, alert.rule_id)

    await audit(db, Action.ALERT_STATUS, Resource.ALERT,
                user_id=current_user.id, username=current_user.username,
                role=current_user.role, resource_id=alert_id,
                detail=f"'{current_user.username}' marked alert as false_positive "
                       f"(rule FP rate: {fp_result.get('fp_rate',0)*100:.0f}%)")

    return {
        "alert_id":   alert_id,
        "status":     "false_positive",
        "rule_impact":fp_result,
    }

@router.get("/rule-history/{rule_id}")
async def rule_history(
    rule_id: str,
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Full version history for a detection rule."""
    return await get_rule_history(db, rule_id)
