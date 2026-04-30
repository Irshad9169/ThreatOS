from __future__ import annotations
import uuid
from datetime import datetime
from sqlalchemy import DateTime, Float, String
from sqlalchemy.orm import Mapped, mapped_column
from threatos.models.base import Base
from threatos.models.raw_event import JSONBCompat

class PurpleTeamRun(Base):
    __tablename__ = "purple_team_runs"
    id:             Mapped[str]      = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    technique_id:   Mapped[str]      = mapped_column(String(20),   nullable=False)
    chain_id:       Mapped[str|None] = mapped_column(String(36),   nullable=True)
    emulated_event: Mapped[dict]     = mapped_column(JSONBCompat,  nullable=False, default=dict)
    rules_expected: Mapped[list]     = mapped_column(JSONBCompat,  nullable=False, default=list)
    rules_fired:    Mapped[list]     = mapped_column(JSONBCompat,  nullable=False, default=list)
    rules_missed:   Mapped[list]     = mapped_column(JSONBCompat,  nullable=False, default=list)
    detection_rate: Mapped[float]    = mapped_column(Float,        nullable=False, default=0.0)
    verdict:        Mapped[str]      = mapped_column(String(10),   nullable=False, default="unknown")
    run_by:         Mapped[str|None] = mapped_column(String(100),  nullable=True)
    notes:          Mapped[str|None] = mapped_column(String(1000), nullable=True)
    run_at:         Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
