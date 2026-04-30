from __future__ import annotations
import uuid, json
from datetime import datetime
from sqlalchemy import DateTime, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator, Text
from threatos.models.base import Base

class JSONBCompat(TypeDecorator):
    """
    Stores JSON data as JSONB on PostgreSQL, TEXT on SQLite.
    Always serialises to string on bind so asyncpg never receives
    raw Python dicts/lists directly.
    """
    impl = Text
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import JSONB
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(Text())

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if dialect.name == "postgresql":
            # asyncpg handles dict/list natively via JSONB descriptor
            return value
        # SQLite — serialise to string
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if dialect.name == "postgresql":
            # asyncpg already deserialises JSONB to Python objects
            return value
        if isinstance(value, (dict, list)):
            return value
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value

class RawEvent(Base):
    __tablename__ = "raw_events"
    id:          Mapped[str]      = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    log_source:  Mapped[str]      = mapped_column(String(30), nullable=False)
    raw_payload: Mapped[dict]     = mapped_column(JSONBCompat, nullable=False, default=dict)
    normalized:  Mapped[dict]     = mapped_column(JSONBCompat, nullable=True)
    hash:        Mapped[str|None] = mapped_column(String(64), nullable=True)
    __table_args__ = (
        UniqueConstraint("hash", name="uq_raw_events_hash"),
        Index("ix_raw_events_received_at", "received_at"),
        Index("ix_raw_events_log_source",  "log_source"),
        {"postgresql_partition_by": "RANGE (received_at)"},
    )
