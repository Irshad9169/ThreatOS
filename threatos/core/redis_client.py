from __future__ import annotations
import json, logging
from functools import lru_cache
import redis.asyncio as aioredis
from redis.asyncio.retry import Retry
from redis.backoff import ExponentialBackoff
from redis.exceptions import BusyLoadingError, ConnectionError, TimeoutError
from threatos.core.settings import settings

log = logging.getLogger(__name__)

def _make_client() -> aioredis.Redis:
    retry = Retry(
        ExponentialBackoff(cap=10, base=0.5), retries=3,
        supported_errors=(BusyLoadingError, ConnectionError, TimeoutError),
    )
    return aioredis.from_url(
        settings.redis_url, decode_responses=True,
        retry=retry, retry_on_timeout=True,
        socket_connect_timeout=5, socket_timeout=5,
        protocol=2,  # force RESP2 — this deployment's Redis predates HELLO/RESP3 (Redis 6.0+)
    )

@lru_cache(maxsize=1)
def get_redis_client() -> aioredis.Redis:
    return _make_client()

async def check_redis_health() -> bool:
    try:
        await get_redis_client().ping()
        return True
    except Exception as exc:
        log.warning("Redis health check failed: %s", exc)
        return False

async def publish_alert(alert_dict: dict) -> None:
    try:
        await get_redis_client().publish(
            "threatos:alerts:live", json.dumps(alert_dict),
        )
    except Exception as exc:
        log.warning("Failed to publish alert: %s", exc)

async def get_stream_lag(stream: str, group: str) -> int:
    try:
        pending = await get_redis_client().xpending(stream, group)
        return int(pending.get("pending", 0))
    except Exception:
        return -1
