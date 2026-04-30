from __future__ import annotations
import time
from prometheus_client import (
    Counter, Gauge, Histogram, Info,
    CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST,
    multiprocess, REGISTRY,
)

# ── Metrics definitions ───────────────────────────────────────────────────────

# API request metrics
http_requests_total = Counter(
    "threatos_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status_code"],
)

http_request_duration = Histogram(
    "threatos_http_request_duration_seconds",
    "HTTP request duration",
    ["method", "endpoint"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

# Detection metrics
alerts_created_total = Counter(
    "threatos_alerts_created_total",
    "Total alerts created",
    ["technique_id", "tactic", "severity"],
)

alerts_by_status = Gauge(
    "threatos_alerts_by_status",
    "Current alert counts by status",
    ["status"],
)

events_ingested_total = Counter(
    "threatos_events_ingested_total",
    "Total events ingested",
    ["log_source"],
)

rules_loaded = Gauge(
    "threatos_rules_loaded_total",
    "Number of detection rules currently loaded in engine",
)

rules_enabled = Gauge(
    "threatos_rules_enabled_total",
    "Number of enabled detection rules in database",
)

# Worker metrics
worker_lag = Gauge(
    "threatos_worker_lag_events",
    "Number of unprocessed events in Redis stream",
)

worker_batch_duration = Histogram(
    "threatos_worker_batch_duration_seconds",
    "Time to process one worker batch",
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0],
)

rule_eval_duration = Histogram(
    "threatos_rule_eval_duration_milliseconds",
    "Rule evaluation time per event",
    ["rule_id"],
    buckets=[0.1, 0.5, 1.0, 5.0, 10.0, 50.0, 100.0],
)

# Coverage metrics
attck_coverage_pct = Gauge(
    "threatos_attck_coverage_percent",
    "ATT&CK technique coverage percentage",
)

attck_techniques_covered = Gauge(
    "threatos_attck_techniques_covered",
    "Number of ATT&CK techniques with at least one rule",
)

attck_techniques_total = Gauge(
    "threatos_attck_techniques_total",
    "Total ATT&CK techniques in the matrix",
)

# System metrics
active_users = Gauge(
    "threatos_active_users_total",
    "Total active user accounts",
)

db_pool_size = Gauge(
    "threatos_db_pool_size",
    "Database connection pool size",
)

db_pool_checked_out = Gauge(
    "threatos_db_pool_checked_out",
    "Database connections currently checked out",
)

# Health metrics
component_health = Gauge(
    "threatos_component_health",
    "Component health status (1=ok, 0=error)",
    ["component"],
)

# Version info
app_info = Info(
    "threatos_app",
    "ThreatOS application info",
)
app_info.info({
    "version": "0.1.0",
    "environment": "production",
})

# ── Middleware ────────────────────────────────────────────────────────────────

class PrometheusMiddleware:
    """FastAPI middleware to track HTTP request metrics."""

    def __init__(self, app):
        self.app = app
        # Endpoints to skip (too noisy)
        self._skip = {"/health", "/metrics", "/favicon.ico"}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in self._skip:
            await self.app(scope, receive, send)
            return

        method    = scope.get("method", "UNKNOWN")
        # Normalise path — replace UUIDs with {id}
        import re
        norm_path = re.sub(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '{id}', path)

        start     = time.perf_counter()
        status    = [200]

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status[0] = message.get("status", 200)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration = time.perf_counter() - start
            http_requests_total.labels(
                method=method,
                endpoint=norm_path,
                status_code=str(status[0]),
            ).inc()
            http_request_duration.labels(
                method=method,
                endpoint=norm_path,
            ).observe(duration)

# ── Metrics collection helpers ────────────────────────────────────────────────

async def update_db_metrics(db) -> None:
    """Update database-sourced metrics. Call periodically."""
    from sqlalchemy import func, select, text
    from threatos.models.alert import Alert
    from threatos.models.detection_rule import DetectionRule
    from threatos.models.user import User
    from threatos.models.coverage_matrix import CoverageMatrix

    try:
        # Alert counts by status
        result = await db.execute(
            select(Alert.status, func.count(Alert.id).label("cnt"))
            .group_by(Alert.status)
        )
        for row in result:
            alerts_by_status.labels(status=row.status).set(row.cnt)

        # Rules
        r_enabled = await db.execute(
            select(func.count(DetectionRule.id))
            .where(DetectionRule.enabled.is_(True))
        )
        rules_enabled.set(int(r_enabled.scalar() or 0))

        # Coverage
        cov_total = await db.execute(
            select(func.count(CoverageMatrix.technique_id)))
        cov_covered = await db.execute(
            select(func.count(CoverageMatrix.technique_id))
            .where(CoverageMatrix.covered.is_(True))
        )
        total = int(cov_total.scalar() or 0)
        covered = int(cov_covered.scalar() or 0)
        attck_techniques_total.set(total)
        attck_techniques_covered.set(covered)
        if total > 0:
            attck_coverage_pct.set(round(covered / total * 100, 1))

        # Users
        u_count = await db.execute(
            select(func.count(User.id)).where(User.is_active.is_(True)))
        active_users.set(int(u_count.scalar() or 0))

    except Exception as exc:
        import logging
        logging.getLogger(__name__).debug("Metrics update failed: %s", exc)
