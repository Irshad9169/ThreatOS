"""
tests/conftest.py
──────────────────
Shared async fixtures. SQLite in-memory — no Docker needed.
Strips postgresql_partition_by from partitioned models.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from threatos.models import Base, RawEvent

TEST_DB_URL  = "sqlite+aiosqlite:///:memory:"
_PARTITIONED = [RawEvent]   # only RawEvent has postgresql_partition_by


def _strip_pg_args(model_class):
    return tuple(
        a for a in model_class.__table_args__
        if not isinstance(a, dict)
    )


@pytest_asyncio.fixture(scope="function")
async def db_session():
    saved = {m: m.__table_args__ for m in _PARTITIONED}
    for m in _PARTITIONED:
        m.__table_args__ = _strip_pg_args(m)

    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        yield session

    await engine.dispose()
    for m, args in saved.items():
        m.__table_args__ = args


@pytest_asyncio.fixture(scope="function")
async def test_client(db_session: AsyncSession):
    from threatos.main import app
    from threatos.core.database import get_db

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        yield client

    app.dependency_overrides.clear()
