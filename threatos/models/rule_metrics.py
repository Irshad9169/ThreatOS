from __future__ import annotations
from datetime import datetime
from sqlalchemy import Boolean, DateTime, Float, Index, BigInteger, String
from sqlalchemy.orm import Mapped, mapped_column
from threatos.models.base import Base

class RuleMetrics(Base):
    __tablename__ = "rule_metrics"
    rule_id:           Mapped[str]          = mapped_column(String(36),  primary_key=True)
    rule_name:         Mapped[str|None]     = mapped_column(String(200), nullable=True)
    total_evals:       Mapped[int]          = mapped_column(BigInteger,  nullable=False, default=0)
    total_matches:     Mapped[int]          = mapped_column(BigInteger,  nullable=False, default=0)
    total_fp:          Mapped[int]          = mapped_column(BigInteger,  nullable=False, default=0)
    avg_eval_ms:       Mapped[float]        = mapped_column(Float,       nullable=False, default=0.0)
    last_eval_at:      Mapped[datetime|None]= mapped_column(DateTime(timezone=True), nullable=True)
    last_match_at:     Mapped[datetime|None]= mapped_column(DateTime(timezone=True), nullable=True)
    fp_rate:           Mapped[float]        = mapped_column(Float,       nullable=False, default=0.0)
    suggested_disable: Mapped[bool]         = mapped_column(Boolean,     nullable=False, default=False)
    __table_args__ = (
        Index("ix_rule_metrics_fp", "fp_rate"),
    )
