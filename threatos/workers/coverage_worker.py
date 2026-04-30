from __future__ import annotations
import asyncio, logging, signal
from typing import Any
from threatos.core.attck_kb import get_cache_size, load_attck_bundle
from threatos.core.database import get_db_context
from threatos.core.settings import settings
from threatos.services.coverage_service import refresh_coverage

log = logging.getLogger(__name__)
_SHUTDOWN = asyncio.Event()

def _handle_signal(sig: int, _frame: Any) -> None:
    log.info("Coverage worker signal %d — shutting down", sig)
    _SHUTDOWN.set()

async def _load_attck() -> int:
    for attempt in range(1, 4):
        try:
            techniques = await load_attck_bundle(settings.attck_bundle_url)
            log.info("ATT&CK bundle loaded: %d techniques", len(techniques))
            return len(techniques)
        except Exception as exc:
            log.warning("ATT&CK load failed (attempt %d/3): %s", attempt, exc)
            if attempt < 3: await asyncio.sleep(5 * attempt)
    return 0

async def _do_refresh() -> None:
    if get_cache_size() == 0:
        await _load_attck()
    if get_cache_size() == 0:
        log.warning("Skipping coverage refresh: no ATT&CK techniques in cache")
        return
    try:
        async with get_db_context() as db:
            summary = await refresh_coverage(db)
        log.info("Coverage refreshed — total=%d covered=%d pct=%.1f%%",
                 summary.total_techniques, summary.covered, summary.coverage_pct)
    except Exception as exc:
        log.error("Coverage refresh failed: %s", exc)

async def run_coverage_worker() -> None:
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)
    log.info("Coverage worker starting — interval=%ds",
             settings.coverage_refresh_interval_seconds)
    await _load_attck()
    await _do_refresh()
    interval = settings.coverage_refresh_interval_seconds
    while not _SHUTDOWN.is_set():
        for _ in range(interval * 5):
            if _SHUTDOWN.is_set(): break
            await asyncio.sleep(0.2)
        if not _SHUTDOWN.is_set():
            log.info("Coverage worker running scheduled refresh")
            await _do_refresh()
    log.info("Coverage worker shut down")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_coverage_worker())
