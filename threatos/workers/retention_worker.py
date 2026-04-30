"""
workers/retention_worker.py
────────────────────────────
Daily data retention worker.
Deletes expired raw_events, closed alerts, old scans,
expired tokens, and old login attempts per policy in .env.

Runs as a separate systemd service or can be invoked via cron.
"""
from __future__ import annotations
import asyncio, logging, signal
from typing import Any
from threatos.core.database import get_db_context
from threatos.services.retention_service import run_retention

log = logging.getLogger(__name__)
_SHUTDOWN = asyncio.Event()

def _handle_signal(sig: int, _frame: Any) -> None:
    log.info("Retention worker signal %d — shutting down", sig)
    _SHUTDOWN.set()

async def run_retention_worker() -> None:
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)

    log.info("Retention worker starting")

    # Run immediately on start
    try:
        async with get_db_context() as db:
            deleted = await run_retention(db)
        log.info("Initial retention run: %s", deleted)
    except Exception as exc:
        log.error("Retention run failed: %s", exc)

    # Then run every 24 hours
    INTERVAL = 86400  # 24 hours
    while not _SHUTDOWN.is_set():
        for _ in range(INTERVAL * 5):
            if _SHUTDOWN.is_set(): break
            await asyncio.sleep(0.2)
        if not _SHUTDOWN.is_set():
            try:
                async with get_db_context() as db:
                    deleted = await run_retention(db)
                log.info("Daily retention run: %s", deleted)
            except Exception as exc:
                log.error("Retention run failed: %s", exc)

    log.info("Retention worker shut down")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s")
    asyncio.run(run_retention_worker())
