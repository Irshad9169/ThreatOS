from __future__ import annotations
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncSession, async_sessionmaker, create_async_engine,
)
from threatos.core.settings import settings

# ── Engine configuration ──────────────────────────────────────────────────────
# Pool settings tuned for production:
# - pool_size: persistent connections kept open
# - max_overflow: extra connections allowed under peak load
# - pool_timeout: wait time before giving up on getting a connection
# - pool_recycle: recycle connections after N seconds (prevents stale connections)
# - pool_pre_ping: test connection before use (detects dead connections)
# - connect_args: statement_cache_size=0 required for PgBouncer transaction mode

_PGBOUNCER_MODE = os.environ.get("PGBOUNCER_MODE", "false").lower() == "true"

_connect_args: dict = {}
if _PGBOUNCER_MODE:
    # PgBouncer transaction mode requires disabling prepared statements
    _connect_args = {"statement_cache_size": 0}

engine = create_async_engine(
    settings.database_url,
    pool_size=settings.database_pool_size,
    max_overflow=settings.database_max_overflow,
    pool_timeout=30,
    pool_recycle=1800,   # recycle connections every 30 minutes
    pool_pre_ping=True,  # test connection health before use
    echo=False,
    connect_args=_connect_args,
)

AsyncSessionFactory = async_sessionmaker(
    engine,
    expire_on_commit=False,
    class_=AsyncSession,
)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionFactory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise

@asynccontextmanager
async def get_db_context():
    async with AsyncSessionFactory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
