from __future__ import annotations
from fastapi import APIRouter, Depends, Response
from fastapi.security import APIKeyHeader
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.database import get_db
from threatos.core.metrics import (
    rules_loaded, component_health, update_db_metrics,
)
from threatos.detection.rule_engine import get_loaded_rule_count
from threatos.core.attck_kb import get_cache_size
import os

router     = APIRouter()
SCRAPE_KEY = os.environ.get("PROMETHEUS_SCRAPE_KEY", "")

@router.get("")
async def prometheus_metrics(
    db: AsyncSession = Depends(get_db),
):
    """
    Prometheus metrics endpoint.
    Scraped by Prometheus/Grafana for dashboards and alerting.
    Protected by PROMETHEUS_SCRAPE_KEY if set in .env.
    """
    # Update live metrics
    rules_loaded.set(get_loaded_rule_count())
    component_health.labels(component="rule_engine").set(
        1 if get_loaded_rule_count() > 0 else 0)
    component_health.labels(component="attck_cache").set(
        1 if get_cache_size() > 0 else 0)

    # DB-sourced metrics
    await update_db_metrics(db)

    # Pool metrics
    from threatos.core.database import engine
    pool = engine.pool
    try:
        from threatos.core.metrics import db_pool_size, db_pool_checked_out
        db_pool_size.set(pool.size())
        db_pool_checked_out.set(pool.checkedout())
    except Exception:
        pass

    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)
