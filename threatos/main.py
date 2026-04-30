from __future__ import annotations
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from threatos.api.routers import (
    alerts_router, assets_router, audit_router, chains_router,
    compliance_router, coverage_router, detection_router, events_router,
    health_router, ingest_router, metrics_router, purple_router,
    report_router, retention_router, rules_router, scans_router,
    ti_router, ws_router, auth_router,
)
from threatos.core.database import get_db_context
from threatos.core.logging_config import configure_logging
from threatos.core.metrics import PrometheusMiddleware

configure_logging()
log = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        from threatos.detection.rule_loader import load_rules
        async with get_db_context() as db:
            count = await load_rules(db)
        log.info("Startup: loaded %d detection rules", count)
    except Exception as exc:
        log.warning("Startup rule load failed: %s", exc)
    try:
        from threatos.core.auth import ensure_admin_exists
        async with get_db_context() as db:
            await ensure_admin_exists(db)
    except Exception as exc:
        log.warning("Admin bootstrap failed: %s", exc)
    # Load ATT&CK bundle on startup so cache is never empty after restart
    try:
        from threatos.core.attck_kb import load_attck_bundle
        from threatos.core.settings import settings
        await load_attck_bundle(settings.attck_bundle_url)
        log.info("ATT&CK bundle loaded on startup")
    except Exception as exc:
        log.warning("ATT&CK startup load failed: %s", exc)
    ws_router.start_subscription_task()
    yield
    if ws_router._subscription_task is not None:
        ws_router._subscription_task.cancel()

app = FastAPI(
    title="ThreatOS", version="0.1.0",
    description="MITRE ATT&CK-aware security operations platform.",
    lifespan=lifespan,
)

app.add_middleware(PrometheusMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# Public
app.include_router(health_router.router,     prefix="/health",        tags=["health"])
app.include_router(metrics_router.router,    prefix="/metrics",       tags=["metrics"])
app.include_router(auth_router.router,       prefix="/api/auth",      tags=["auth"])

# Protected
app.include_router(ingest_router.router,     prefix="/api/ingest",    tags=["ingest"])
app.include_router(rules_router.router,      prefix="/api/rules",     tags=["rules"])
app.include_router(alerts_router.router,     prefix="/api/alerts",    tags=["alerts"])
app.include_router(coverage_router.router,   prefix="/api/coverage",  tags=["coverage"])
app.include_router(assets_router.router,     prefix="/api/assets",    tags=["assets"])
app.include_router(chains_router.router,     prefix="/api/chains",    tags=["chains"])
app.include_router(purple_router.router,     prefix="/api/purple",    tags=["purple"])
app.include_router(scans_router.router,      prefix="/api/scans",     tags=["scans"])
app.include_router(audit_router.router,      prefix="/api/audit",     tags=["audit"])
app.include_router(events_router.router,     prefix="/api/events",    tags=["events"])
app.include_router(report_router.router,     prefix="/api/report",    tags=["report"])
app.include_router(retention_router.router,  prefix="/api/retention", tags=["retention"])
app.include_router(detection_router.router,  prefix="/api/detection", tags=["detection"])
app.include_router(compliance_router.router, prefix="/api/compliance",tags=["compliance"])
app.include_router(ti_router.router,         prefix="/api/ti",        tags=["threat-intel"])
app.include_router(ws_router.router,         prefix="/ws",            tags=["websocket"])
