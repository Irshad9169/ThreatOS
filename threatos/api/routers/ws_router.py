from __future__ import annotations
import asyncio, logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from threatos.core.redis_client import get_redis_client

router  = APIRouter()
log     = logging.getLogger(__name__)
_CLIENTS: set[WebSocket] = set()
_subscription_task = None

async def _broadcast(message: str) -> None:
    dead = set()
    for ws in list(_CLIENTS):
        try: await ws.send_text(message)
        except Exception: dead.add(ws)
    _CLIENTS.difference_update(dead)

async def _subscribe_loop() -> None:
    while True:
        try:
            pubsub = get_redis_client().pubsub()
            await pubsub.subscribe("threatos:alerts:live")
            async for message in pubsub.listen():
                if message["type"] == "message":
                    await _broadcast(message["data"])
        except asyncio.CancelledError: break
        except Exception as exc:
            log.warning("Redis pubsub error: %s — reconnecting in 2s", exc)
            await asyncio.sleep(2)

def start_subscription_task() -> None:
    global _subscription_task
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running() and _subscription_task is None:
            _subscription_task = loop.create_task(_subscribe_loop())
    except RuntimeError: pass

@router.websocket("/alerts")
async def alerts_ws(websocket: WebSocket) -> None:
    await websocket.accept()
    _CLIENTS.add(websocket)
    try:
        while True: await websocket.receive_text()
    except WebSocketDisconnect: pass
    finally: _CLIENTS.discard(websocket)
