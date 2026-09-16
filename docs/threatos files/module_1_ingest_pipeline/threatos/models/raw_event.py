"""
models/raw_event.py
────────────────────
RawEvent — the immutable record of every ingested log line.

Fix v3: UUID primary key uses Python default (uuid.uuid4) instead of
        server_default so tests work on SQLite. Identical behaviour
        on PostgreSQL.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Index, String, UniqueConstraint
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator, TEXT

from threatos.models.base import Base


class JSONBCompat(TypeDecorator):
    """JSONB on PostgreSQL, JSON on everything else (SQLite in tests)."""
    impl = TEXT
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if dialect.name != "postgresql":
            import json
            return json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if dialect.name != "postgresql" and isinstance(value, str):
            import json
            return json.loads(value)
        return value


class RawEvent(Base):
    __tablename__ = "raw_events"

    # Python-side default — works on both PostgreSQL and SQLite
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        primary_key=True,
        nullable=False,
    )
    log_source: Mapped[str] = mapped_column(String(30), nullable=False)
    raw_payload: Mapped[dict] = mapped_column(JSONBCompat, nullable=False, default=dict)
    normalized: Mapped[dict | None] = mapped_column(JSONBCompat, nullable=True)
    hash: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)

    __table_args__ = (
        Index("ix_raw_events_received_at", "received_at"),
        Index("ix_raw_events_log_source",  "log_source"),
        UniqueConstraint("hash", name="uq_raw_events_hash"),
        {"postgresql_partition_by": "RANGE (received_at)"},
    )

    def __repr__(self) -> str:
        return (
            f"<RawEvent id={self.id} "
            f"source={self.log_source!r} "
            f"at={self.received_at}>"
        )
