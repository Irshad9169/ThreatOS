"""
workers/coverage_worker.py
───────────────────────────
Periodic ATT&CK coverage refresh worker.

Responsibilities
────────────────
  1. At startup: download the ATT&CK STIX bundle and seed the cache
  2. Every coverage_refresh_interval_seconds: re-run refresh_coverage()
     so the matrix stays current as rules are added/removed.

The coverage matrix is a materialised view — it does not update
automatically when rules change.  This worker keeps it fresh.

Oracle Linux 8 deployment
──────────────────────────
  python3.11 -m threatos.workers.coverage_worker
  Runs as a long-lived process managed by systemd.
  See docs/oracle_linux_8_setup.md for the service unit file.
"""
from __future__ import annotations

import asyncio
import logging
import signal
from datetime import UTC, datetime
from typing import Any

from threatos.core.attck_kb import get_cache_size, load_attck_bundle
from threatos.core.database import get_db_context
from threatos.core.settings import settings
from threatos.services.coverage_service import refresh_coverage

log = logging.getLogger(__name__)

_SHUTDOWN = asyncio.Event()


def _handle_signal(sig: int, _frame: Any) -> None:
    log.info("Coverage worker received signal %d — shutting down", sig)
    _SHUTDOWN.set()


async def _load_attck() -> int:
    """Download + parse ATT&CK bundle. Retries 3 times with backoff."""
    for attempt in range(1, 4):
        try:
            techniques = await load_attck_bundle(settings.attck_bundle_url)
            count = len(techniques)
            log.info("ATT&CK bundle loaded: %d techniques", count)
            return count
        except Exception as exc:
            log.warning(
                "ATT&CK bundle load failed (attempt %d/3): %s", attempt, exc
            )
            if attempt < 3:
                await asyncio.sleep(5 * attempt)
    log.error("Could not load ATT&CK bundle after 3 attempts — "
              "coverage matrix will remain empty until next interval")
    return 0


async def _do_refresh() -> None:
    """Run one full coverage matrix refresh cycle."""
    if get_cache_size() == 0:
        log.info("ATT&CK cache empty — attempting bundle reload before refresh")
        await _load_attck()

    if get_cache_size() == 0:
        log.warning("Skipping coverage refresh: no ATT&CK techniques in cache")
        return

    try:
        async with get_db_context() as db:
            summary = await refresh_coverage(db)
        log.info(
            "Coverage refreshed — total=%d covered=%d gaps=%d pct=%.1f%%",
            summary.total_techniques,
            summary.covered,
            summary.gaps,
            summary.coverage_pct,
        )
    except Exception as exc:
        log.error("Coverage refresh failed: %s", exc)


async def run_coverage_worker() -> None:
    """
    Main loop.  Downloads ATT&CK at startup then refreshes on interval.
    Graceful shutdown on SIGTERM / SIGINT.
    """
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)

    log.info(
        "Coverage worker starting — interval=%ds",
        settings.coverage_refresh_interval_seconds,
    )

    # Initial load + refresh
    await _load_attck()
    await _do_refresh()

    interval = settings.coverage_refresh_interval_seconds

    while not _SHUTDOWN.is_set():
        # Sleep in short segments so SIGTERM is handled promptly
        for _ in range(interval * 5):   # check every 200ms
            if _SHUTDOWN.is_set():
                break
            await asyncio.sleep(0.2)

        if not _SHUTDOWN.is_set():
            log.info("Coverage worker running scheduled refresh")
            await _do_refresh()

    log.info("Coverage worker shut down")


if __name__ == "__main__":
    import structlog
    structlog.configure()
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_coverage_worker())
