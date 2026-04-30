from __future__ import annotations
from datetime import datetime
from sqlalchemy import Boolean, DateTime, Float, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from threatos.models.base import Base
from threatos.models.raw_event import JSONBCompat

class CoverageMatrix(Base):
    __tablename__ = "coverage_matrix"
    technique_id:   Mapped[str]          = mapped_column(String(20),  primary_key=True)
    technique_name: Mapped[str|None]     = mapped_column(String(200), nullable=True)
    tactic:         Mapped[str|None]     = mapped_column(String(60),  nullable=True)
    rule_count:     Mapped[int]          = mapped_column(Integer, nullable=False, default=0)
    confidence_avg: Mapped[float]        = mapped_column(Float,   nullable=False, default=0.0)
    covered:        Mapped[bool]         = mapped_column(Boolean, nullable=False, default=False)
    last_triggered: Mapped[datetime|None]= mapped_column(DateTime(timezone=True), nullable=True)
    platforms:      Mapped[list]         = mapped_column(JSONBCompat, nullable=False, default=list)
    priority_gap:   Mapped[bool]         = mapped_column(Boolean, nullable=False, default=False)
    refreshed_at:   Mapped[datetime|None]= mapped_column(DateTime(timezone=True), nullable=True)
    __table_args__ = (
        Index("ix_coverage_tactic",   "tactic"),
        Index("ix_coverage_covered",  "covered"),
        Index("ix_coverage_priority", "priority_gap"),
    )
