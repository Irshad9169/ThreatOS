from __future__ import annotations
import uuid
from datetime import datetime
from sqlalchemy import Boolean, CheckConstraint, DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from threatos.models.base import Base
from threatos.models.raw_event import JSONBCompat

VALID_STATUSES = ("open", "investigating", "escalated", "closed", "false_positive")

class Alert(Base):
    __tablename__ = "alerts"
    id:                Mapped[str]       = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id:           Mapped[str|None]  = mapped_column(String(100), nullable=True)
    rule_name:         Mapped[str|None]  = mapped_column(String(200), nullable=True)
    event_id:          Mapped[str|None]  = mapped_column(String(100), nullable=True)
    technique_id:      Mapped[str]       = mapped_column(String(20),  nullable=False)
    tactic:            Mapped[str]       = mapped_column(String(60),  nullable=False)
    severity:          Mapped[int]       = mapped_column(Integer, nullable=False)
    confidence:        Mapped[float]     = mapped_column(Float,   nullable=False)
    asset_criticality: Mapped[int]       = mapped_column(Integer, nullable=False, default=2)
    risk_score:        Mapped[float]     = mapped_column(Float,   nullable=False)
    entity_host:       Mapped[str|None]  = mapped_column(String(255), nullable=True)
    entity_user:       Mapped[str|None]  = mapped_column(String(255), nullable=True)
    entity_process:    Mapped[str|None]  = mapped_column(String(255), nullable=True)
    entity_ip:         Mapped[str|None]  = mapped_column(String(45),  nullable=True)
    status:            Mapped[str]       = mapped_column(String(20), nullable=False, default="open")
    created_at:        Mapped[datetime]  = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at:        Mapped[datetime]  = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at:         Mapped[datetime|None] = mapped_column(DateTime(timezone=True), nullable=True)
    description:       Mapped[str|None]  = mapped_column(String(500), nullable=True)
    raw_match:         Mapped[dict|None] = mapped_column(JSONBCompat, nullable=True)
    # Added by migration 007 (ALTER TABLE) — declared here so the ORM
    # actually knows about them; previously missing, which meant
    # Alert.ti_enriched raised AttributeError in queries and
    # alert.ti_enriched = True silently never persisted (SQLAlchemy's
    # unit-of-work only tracks declared mapped columns).
    ti_enriched:       Mapped[bool]      = mapped_column(Boolean, nullable=False, default=False)
    ti_verdict:        Mapped[str|None]  = mapped_column(String(20), nullable=True)
    ti_summary:        Mapped[str|None]  = mapped_column(Text, nullable=True)
    __table_args__ = (
        CheckConstraint("status IN ('open','investigating','escalated','closed','false_positive')", name="ck_alerts_status"),
        Index("ix_alerts_technique_id", "technique_id"),
        Index("ix_alerts_status",       "status"),
        Index("ix_alerts_risk_score",   "risk_score"),
        Index("ix_alerts_entity_host",  "entity_host"),
        Index("ix_alerts_created_at",   "created_at"),
    )
