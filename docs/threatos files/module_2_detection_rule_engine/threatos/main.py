"""
main.py — ThreatOS FastAPI application.

Startup sequence (lifespan):
  1. Load detection rules into the in-memory engine
  2. Start the WebSocket alert relay background task
  3. Yield (app serves requests)
  4. Cancel background task on shutdown

All routers registered only after their integration tests pass.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from threatos.api.routers import (
    alerts_router,
    assets_router,
    chains_router,
    coverage_router,
    ingest_router,
    purple_router,
    rules_router,
    scans_router,
)
from threatos.api.routers import ws_router
from threatos.core.database import get_db_context

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ───────────────────────────────────────────────────────────────
    # Load enabled detection rules into the in-memory engine
    try:
        from threatos.detection.rule_loader import load_rules
        async with get_db_context() as db:
            count = await load_rules(db)
        log.info("Startup: loaded %d detection rules", count)
    except Exception as exc:
        log.warning("Startup: could not load rules (DB may not be ready): %s", exc)

    # Start the WebSocket alert relay (subscribes to Redis pubsub)
    ws_router.start_subscription_task()

    yield

    # ── Shutdown ──────────────────────────────────────────────────────────────
    if ws_router._subscription_task is not None:
        ws_router._subscription_task.cancel()


app = FastAPI(
    title="ThreatOS",
    version="0.1.0",
    description=(
        "MITRE ATT&CK-aware security operations platform. "
        "SIEM · Detection · Correlation · Purple Team · Nmap."
    ),
    lifespan=lifespan,
)

# ── API routes ────────────────────────────────────────────────────────────────
app.include_router(ingest_router.router,   prefix="/api/ingest",   tags=["ingest"])
app.include_router(rules_router.router,    prefix="/api/rules",    tags=["rules"])
app.include_router(alerts_router.router,   prefix="/api/alerts",   tags=["alerts"])
app.include_router(coverage_router.router, prefix="/api/coverage", tags=["coverage"])
app.include_router(assets_router.router,   prefix="/api/assets",   tags=["assets"])
app.include_router(chains_router.router,   prefix="/api/chains",   tags=["chains"])
app.include_router(purple_router.router,   prefix="/api/purple",   tags=["purple"])
app.include_router(scans_router.router,    prefix="/api/scans",    tags=["scans"])

# ── WebSocket ─────────────────────────────────────────────────────────────────
app.include_router(ws_router.router, prefix="/ws", tags=["websocket"])
