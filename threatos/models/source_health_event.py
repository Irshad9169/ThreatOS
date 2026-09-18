from __future__ import annotations
import uuid
from datetime import datetime
from sqlalchemy import DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column
from threatos.models.base import Base

class SourceHealthEvent(Base):
    """One row per URL Scanner source per investigation — lets us detect a
    silently degraded/broken external dependency (e.g. a provider tightening
    its auth policy) instead of an analyst discovering it via bad results."""
    __tablename__ = "source_health_events"
    id:          Mapped[str]        = mapped_column(String(36), primary_key=True,
                                          default=lambda: str(uuid.uuid4()))
    source:      Mapped[str]        = mapped_column(String(30), nullable=False)
    outcome:     Mapped[str]        = mapped_column(String(20), nullable=False)  # ok | no_key | error
    message:     Mapped[str | None] = mapped_column(String(500), nullable=True)
    occurred_at: Mapped[datetime]   = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (
        Index("ix_source_health_source_occurred", "source", "occurred_at"),
    )
