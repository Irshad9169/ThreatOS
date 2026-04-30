from __future__ import annotations
import uuid
from datetime import datetime
from sqlalchemy import Boolean, CheckConstraint, DateTime, Float, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from threatos.models.base import Base
from threatos.models.raw_event import JSONBCompat

CHAIN_STATUSES = ("open","investigating","closed")

class AttackChain(Base):
    __tablename__ = "attack_chains"
    id:               Mapped[str]      = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    host:             Mapped[str]      = mapped_column(String(255), nullable=False)
    chain_hash:       Mapped[str]      = mapped_column(String(64),  nullable=False, unique=True)
    alert_ids:        Mapped[list]     = mapped_column(JSONBCompat, nullable=False, default=list)
    technique_ids:    Mapped[list]     = mapped_column(JSONBCompat, nullable=False, default=list)
    tactics_observed: Mapped[list]     = mapped_column(JSONBCompat, nullable=False, default=list)
    tactic_count:     Mapped[int]      = mapped_column(Integer, nullable=False, default=1)
    risk_score:       Mapped[float]    = mapped_column(Float,   nullable=False, default=0.0)
    first_seen:       Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen:        Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    duration_seconds: Mapped[int]      = mapped_column(Integer, nullable=False, default=0)
    status:           Mapped[str]      = mapped_column(String(20), nullable=False, default="open")
    is_multi_stage:   Mapped[bool]     = mapped_column(Boolean, nullable=False, default=False)
    __table_args__ = (
        Index("ix_attack_chains_host",         "host"),
        Index("ix_attack_chains_status",       "status"),
        Index("ix_attack_chains_risk_score",   "risk_score"),
        Index("ix_attack_chains_is_multi_stage","is_multi_stage"),
        CheckConstraint("status IN ('open','investigating','closed')", name="ck_attack_chains_status"),
    )
