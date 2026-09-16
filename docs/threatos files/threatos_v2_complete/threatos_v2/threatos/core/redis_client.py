"""
core/redis_client.py
─────────────────────
Shared async Redis client with connection pooling, health-check,
and stream/pubsub helpers.

Used by:
  - ingest_worker.py   (XREADGROUP, XACK, XADD)
  - coverage_worker.py (pubsub for future notifications)
  - purple_router.py   (Phase 2: live score updates)

Oracle Linux 8:
  pip3.11 install redis[hiredis]
  Redis itself runs in Docker (see docker-compose.yml).
"""
from __future__ import annotations

import logging
from functools import lru_cache

import redis.asyncio as aioredis
from redis.asyncio.retry import Retry
from redis.backoff import ExponentialBackoff
from redis.exceptions import BusyLoadingError, ConnectionError, TimeoutError

from threatos.core.settings import settings

log = logging.getLogger(__name__)


def _make_client() -> aioredis.Redis:
    """
    Create a connection-pooled async Redis client.

    Retry policy: exponential back-off on connection errors,
    up to 3 retries. This handles transient restarts without
    crashing the worker.
    """
    retry = Retry(
        ExponentialBackoff(cap=10, base=0.5),
        retries=3,
        supported_errors=(BusyLoadingError, ConnectionError, TimeoutError),
    )
    return aioredis.from_url(
        settings.redis_url,
        decode_responses=True,
        retry=retry,
        retry_on_timeout=True,
        socket_connect_timeout=5,
        socket_timeout=5,
    )


@lru_cache(maxsize=1)
def get_redis_client() -> aioredis.Redis:
    """
    Return the shared Redis client singleton.
    Created once per process; lru_cache ensures only one instance exists.
    Workers call this instead of creating their own connections.
    """
    return _make_client()


async def check_redis_health() -> bool:
    """
    Ping Redis. Returns True if reachable, False otherwise.
    Used by the /health endpoint (Phase 2).
    """
    try:
        client = get_redis_client()
        await client.ping()
        return True
    except Exception as exc:
        log.warning("Redis health check failed: %s", exc)
        return False


async def publish_alert(alert_dict: dict) -> None:
    """
    Publish a new alert to the threatos:alerts:live pubsub channel.
    Called by the ingest worker after persisting each batch.
    The WebSocket router (ws_router.py) subscribes to this channel
    and fans the message to connected browser clients.
    """
    import json
    try:
        client = get_redis_client()
        await client.publish(
            "threatos:alerts:live",
            json.dumps(alert_dict),
        )
    except Exception as exc:
        log.warning("Failed to publish alert to Redis pubsub: %s", exc)


async def get_stream_lag(stream: str, group: str) -> int:
    """
    Return the number of unprocessed messages in a consumer group.
    Useful for monitoring the ingest worker backlog.
    Returns -1 if the stream or group does not exist.
    """
    try:
        client  = get_redis_client()
        pending = await client.xpending(stream, group)
        return int(pending.get("pending", 0))
    except Exception:
        return -1
