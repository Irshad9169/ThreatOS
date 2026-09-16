"""
api/routers/ws_router.py
─────────────────────────
WebSocket endpoint for real-time alert streaming.

The ingest worker publishes new alerts to the Redis pubsub channel
"threatos:alerts:live" after each batch. This router subscribes
to that channel and fans the JSON payload to every connected browser.

Route:
  WS /ws/alerts

Protocol:
  - Browser connects (no auth in Phase 1 — add JWT query param in Phase 2)
  - Server sends each new alert as a JSON string
  - Browser disconnects cleanly on tab close
  - Server removes disconnected clients silently

Connection management:
  _CLIENTS is a module-level set. On production with multiple uvicorn
  workers, use Redis pubsub fan-out (already in place) rather than
  in-process sets — each worker independently subscribes and fans to
  its own connected clients.

Oracle Linux 8 deployment:
  No OS-specific changes needed. Run uvicorn as normal.
  Ensure no load-balancer strips WebSocket upgrade headers.
  nginx config: proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection "upgrade";
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from threatos.core.redis_client import get_redis_client
from threatos.core.settings import settings

router = APIRouter()
log    = logging.getLogger(__name__)

# Module-level set of connected WebSocket clients
_CLIENTS: set[WebSocket] = set()


async def _broadcast(message: str) -> None:
    """Send a message to all currently connected clients. Remove stale ones."""
    dead: set[WebSocket] = set()
    for ws in list(_CLIENTS):
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)
    _CLIENTS.difference_update(dead)


async def _subscribe_loop() -> None:
    """
    Background task: subscribe to threatos:alerts:live and relay
    every message to connected WebSocket clients.

    Reconnects automatically if Redis drops.
    """
    while True:
        try:
            client  = get_redis_client()
            pubsub  = client.pubsub()
            await pubsub.subscribe("threatos:alerts:live")
            log.info("WebSocket relay subscribed to threatos:alerts:live")

            async for message in pubsub.listen():
                if message["type"] == "message":
                    await _broadcast(message["data"])

        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.warning("Redis pubsub error: %s — reconnecting in 2s", exc)
            await asyncio.sleep(2)


# Start the subscription loop as a background task when the module is imported.
# FastAPI's lifespan should start this; importing here ensures it starts
# even if lifespan is not wired yet.
_subscription_task: asyncio.Task | None = None


def start_subscription_task() -> None:
    """Call this from the FastAPI lifespan to start the relay loop."""
    global _subscription_task
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running() and _subscription_task is None:
            _subscription_task = loop.create_task(_subscribe_loop())
    except RuntimeError:
        pass   # no event loop yet — will be started when lifespan runs


@router.websocket("/alerts")
async def alerts_ws(websocket: WebSocket) -> None:
    """
    WebSocket endpoint. Clients connect here to receive real-time alerts.
    Each message is a JSON string matching the Alert schema.
    """
    await websocket.accept()
    _CLIENTS.add(websocket)
    log.debug("WebSocket client connected (total=%d)", len(_CLIENTS))

    try:
        # Keep the connection alive by reading (and discarding) any
        # client-side messages until the client disconnects.
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        _CLIENTS.discard(websocket)
        log.debug("WebSocket client disconnected (total=%d)", len(_CLIENTS))
