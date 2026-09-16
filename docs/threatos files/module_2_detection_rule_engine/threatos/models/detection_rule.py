"""
models/detection_rule.py
─────────────────────────
DetectionRule — a stored detection rule evaluated against every event.

Fix v2: UUID primary key uses Python default (uuid.uuid4) instead of
        server_default=func.gen_random_uuid() so tests work on SQLite.
        On PostgreSQL this is identical — Python generates the UUID
        before the INSERT statement, so it arrives as a parameter.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger, Boolean, DateTime, Float, Index,
    Integer, String, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from threatos.models.base import Base
from threatos.models.raw_event import JSONBCompat


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    # Python-side default — works on PostgreSQL AND SQLite
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # ── Identity ──────────────────────────────────────────────────────────────
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    author: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # ── ATT&CK mapping ────────────────────────────────────────────────────────
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)
    tactic: Mapped[str] = mapped_column(String(60), nullable=False)

    # ── Targeting ─────────────────────────────────────────────────────────────
    log_sources: Mapped[list] = mapped_column(JSONBCompat, nullable=False, default=list)
    platforms: Mapped[list] = mapped_column(JSONBCompat, nullable=False, default=list)

    # ── Detection logic ───────────────────────────────────────────────────────
    sigma_yaml: Mapped[str | None] = mapped_column(String(10_000), nullable=True)
    detection_ast: Mapped[dict] = mapped_column(JSONBCompat, nullable=False, default=dict)

    # ── Scoring ───────────────────────────────────────────────────────────────
    severity: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.7)

    # ── Tags ──────────────────────────────────────────────────────────────────
    tags: Mapped[list] = mapped_column(JSONBCompat, nullable=False, default=list)

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_triggered: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    trigger_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    __table_args__ = (
        Index("ix_detection_rules_technique_id", "technique_id"),
        Index("ix_detection_rules_tactic",       "tactic"),
        Index("ix_detection_rules_enabled",       "enabled"),
        UniqueConstraint("name", name="uq_detection_rules_name"),
    )

    def __repr__(self) -> str:
        return (
            f"<DetectionRule name={self.name!r} "
            f"technique={self.technique_id} "
            f"enabled={self.enabled}>"
        )
