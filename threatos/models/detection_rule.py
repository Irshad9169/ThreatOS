from __future__ import annotations
import uuid
from datetime import datetime
from sqlalchemy import Boolean, DateTime, Float, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from threatos.models.base import Base
from threatos.models.raw_event import JSONBCompat

class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id:            Mapped[str]       = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name:          Mapped[str]       = mapped_column(String(200), nullable=False, unique=True)
    description:   Mapped[str|None]  = mapped_column(String(1000), nullable=True)
    author:        Mapped[str|None]  = mapped_column(String(100),  nullable=True)
    technique_id:  Mapped[str]       = mapped_column(String(20),  nullable=False)
    tactic:        Mapped[str]       = mapped_column(String(60),  nullable=False)
    log_sources:   Mapped[list]      = mapped_column(JSONBCompat, nullable=False, default=list)
    platforms:     Mapped[list]      = mapped_column(JSONBCompat, nullable=False, default=list)
    sigma_yaml:    Mapped[str|None]  = mapped_column(String(10000), nullable=True)
    detection_ast: Mapped[dict]      = mapped_column(JSONBCompat, nullable=False, default=dict)
    severity:      Mapped[int]       = mapped_column(Integer, nullable=False, default=5)
    confidence:    Mapped[float]     = mapped_column(Float,   nullable=False, default=0.7)
    tags:          Mapped[list]      = mapped_column(JSONBCompat, nullable=False, default=list)
    enabled:       Mapped[bool]      = mapped_column(Boolean, nullable=False, default=True)
    last_triggered:Mapped[datetime|None] = mapped_column(DateTime(timezone=True), nullable=True)
    trigger_count: Mapped[int]       = mapped_column(Integer, nullable=False, default=0)
    __table_args__ = (
        Index("ix_detection_rules_technique_id", "technique_id"),
        Index("ix_detection_rules_enabled",      "enabled"),
    )
